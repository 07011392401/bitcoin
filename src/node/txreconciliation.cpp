// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <unordered_map>
#include <variant>

namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
static const std::string RECON_STATIC_SALT = "Tx Relay Salting";
static const CHashWriter RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    return (CHashWriter(RECON_SALT_HASHER) << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of the transactions we want to announce to the peer along with the state
 * required to reconcile them.
 */
struct ReconciliationSet {
    /** Transactions we want to announce to the peer */
    std::set<uint256> m_wtxids;

    /** This should be called at the end of every reconciliation to avoid unbounded state growth. */
    void Clear() {
        m_wtxids.clear();
    }

};

/**
 * Keeps track of reconciliation-related per-peer state.
 */
class ReconciliationState
{
public:
    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role.
     * */
    bool m_we_initiate;

    /**
     * These values are used to salt short IDs, which is necessary for transaction reconciliations.
     * TODO: they are public to ignore -Wunused-private-field. They should be made private once they
     * are used.
     */
    uint64_t m_k0, m_k1;

    /**
     * Store all transactions which we would relay to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute an efficient representation of this set ("sketch") and use it to efficient reconcile
     * this set with a similar set on the other side of the connection.
     */
    ReconciliationSet m_local_set;

    ReconciliationState(bool we_initiate, uint64_t k0, uint64_t k1) : m_we_initiate(we_initiate), m_k0(k0), m_k1(k1) {}
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
    mutable Mutex m_mutex;

    // Local protocol version
    const uint32_t m_recon_version;

    /**
     * Keeps track of reconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, ReconciliationState>> m_states GUARDED_BY(m_mutex);

public:
    explicit Impl(uint32_t recon_version) : m_recon_version(recon_version) {}

    uint64_t PreRegisterPeer(NodeId peer_id)
    {
        // We do not support reconciliation salt/version updates.
        LOCK(m_mutex);
        assert(m_states.find(peer_id) == m_states.end());

        LogPrint(BCLog::TXRECON, "Pre-register peer=%d.\n", peer_id);
        uint64_t local_recon_salt{GetRand(UINT64_MAX)};

        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        assert(m_states.emplace(peer_id, local_recon_salt).second);
        return local_recon_salt;
    }

    std::optional<bool> RegisterPeer(NodeId peer_id, bool peer_inbound, bool they_may_initiate,
                                     bool they_may_respond, uint32_t peer_recon_version, uint64_t remote_salt)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);

        // A peer should be in the pre-registered state to proceed here.
        if (recon_state == m_states.end()) return std::nullopt;
        uint64_t* local_salt = std::get_if<uint64_t>(&recon_state->second);
        // A peer is already registered. This should be checked by the caller.
        Assume(local_salt);

        // If the peer supports the version which is lower than ours, we downgrade to the version
        // they support. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        const uint32_t recon_version = std::min(peer_recon_version, m_recon_version);
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return false;

        // Must match SENDRECON logic.
        bool they_initiate = they_may_initiate && peer_inbound;
        bool we_initiate = !peer_inbound && they_may_respond;

        // If we ever announce support for both requesting and responding, this will need
        // tie-breaking. For now, this is mutually exclusive because both are based on the
        // inbound flag.
        assert(!(they_initiate && we_initiate));

        // The peer set both flags to false, we treat it as a protocol violation.
        if (!(they_initiate || we_initiate)) return false;

        LogPrint(BCLog::TXRECON, "Register peer=%d with the following params: " /* Continued */
                                 "we_initiate=%i, they_initiate=%i.\n",
                 peer_id, we_initiate, they_initiate);

        uint256 full_salt = ComputeSalt(*local_salt, remote_salt);
        recon_state->second = ReconciliationState(we_initiate, full_salt.GetUint64(0), full_salt.GetUint64(1));
        return true;
    }

    void AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
    {
        assert(txs_to_reconcile.size() > 0);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_mutex);
        auto& recon_state = std::get<ReconciliationState>(m_states.find(peer_id)->second);

        size_t added = 0;
        for (auto& wtxid: txs_to_reconcile) {
            if (recon_state.m_local_set.m_wtxids.insert(wtxid).second) {
                ++added;
            }
        }

        LogPrint(BCLog::NET, "Added %i new transactions to the reconciliation set for peer=%d. " /* Continued */
            "Now the set contains %i transactions.\n", added, peer_id, recon_state.m_local_set.m_wtxids.size());
    }

    void TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove)
    {
        assert(IsPeerRegistered(peer_id));
        LOCK(m_mutex);
        auto recon_state = std::get<ReconciliationState>(m_states.find(peer_id)->second);

        recon_state.m_local_set.m_wtxids.erase(wtxid_to_remove);
    }

    void ForgetPeer(NodeId peer_id)
    {
        LOCK(m_mutex);
        if (m_states.erase(peer_id)) {
            LogPrint(BCLog::TXRECON, "Forget reconciliation state of peer=%d.\n", peer_id);
        }
    }

    bool IsPeerRegistered(NodeId peer_id) const
    {
        LOCK(m_mutex);
        const auto recon_state = m_states.find(peer_id);
        return (recon_state != m_states.end() &&
                std::holds_alternative<ReconciliationState>(recon_state->second));
    }
};

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    return m_impl->PreRegisterPeer(peer_id);
}

std::optional<bool> TxReconciliationTracker::RegisterPeer(NodeId peer_id, bool peer_inbound,
                                                          bool recon_initiator, bool recon_responder,
                                                          uint32_t peer_recon_version, uint64_t remote_salt)
{
    return m_impl->RegisterPeer(peer_id, peer_inbound, recon_initiator, recon_responder,
                                peer_recon_version, remote_salt);
}

void TxReconciliationTracker::AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
{
    m_impl->AddToReconSet(peer_id, txs_to_reconcile);
}

void TxReconciliationTracker::TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove)
{
    m_impl->TryRemovingFromReconSet(peer_id, wtxid_to_remove);
}

void TxReconciliationTracker::ForgetPeer(NodeId peer_id)
{
    m_impl->ForgetPeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}
