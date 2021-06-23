// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <util/check.h>
#include <util/system.h>

#include <unordered_map>
#include <util/hasher.h>
#include <variant>


namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
const HashWriter RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);

/** Announce transactions via full wtxid to a limited number of inbound and outbound peers. */
constexpr double INBOUND_FANOUT_DESTINATIONS_FRACTION = 0.1;
constexpr double OUTBOUND_FANOUT_DESTINATIONS_FRACTION = 0.1;
/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    return (HashWriter(RECON_SALT_HASHER) << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of txreconciliation-related per-peer state.
 */
class TxReconciliationState
{
public:
    /**
     * TODO: This field is public to ignore -Wunused-private-field. Make private once used in
     * the following commits.
     *
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role.
     *
     */
    bool m_we_initiate;

    /**
     * TODO: These fields are public to ignore -Wunused-private-field. Make private once used in
     * the following commits.
     *
     * These values are used to salt short IDs, which is necessary for transaction reconciliations.
     */
    uint64_t m_k0, m_k1;

    /**
     * Store all wtxids which we would announce to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute a compressed representation of this set ("sketch") and use it to efficiently
     * reconcile this set with a set on the peer's side.
     */
    std::set<uint256> m_local_set;

    TxReconciliationState(bool we_initiate, uint64_t k0, uint64_t k1) : m_we_initiate(we_initiate), m_k0(k0), m_k1(k1) {}
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
private:
    mutable Mutex m_txreconciliation_mutex;

    /**
     * We need a ReconciliationTracker-wide randomness to decide to which peers we should flood a
     * given transaction based on a (w)txid.
     */
    const SaltedTxidHasher txidHasher;

    // Local protocol version
    uint32_t m_recon_version;

    /**
     * Keeps track of txreconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, TxReconciliationState>> m_states GUARDED_BY(m_txreconciliation_mutex);

public:
    explicit Impl(uint32_t recon_version) : m_recon_version(recon_version) {}

    uint64_t PreRegisterPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        // We do not support txreconciliation salt/version updates.
        assert(m_states.find(peer_id) == m_states.end());

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Pre-register peer=%d\n", peer_id);
        const uint64_t local_salt{GetRand(UINT64_MAX)};

        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        Assert(m_states.emplace(peer_id, local_salt).second);
        return local_salt;
    }

    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound, bool is_peer_recon_initiator,
                                     bool is_peer_recon_responder, uint32_t peer_recon_version,
                                     uint64_t remote_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);

        // A peer should be in the pre-registered state to proceed here.
        if (recon_state == m_states.end()) return NOT_FOUND;
        uint64_t* local_salt = std::get_if<uint64_t>(&recon_state->second);
        // A peer is already registered. This should be checked by the caller.
        Assume(local_salt);

        // If the peer supports the version which is lower than ours, we downgrade to the version
        // it supports. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        const uint32_t recon_version{std::min(peer_recon_version, m_recon_version)};
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return PROTOCOL_VIOLATION;

        // Must match SENDTXRCNCL logic.
        const bool they_initiate = is_peer_recon_initiator && is_peer_inbound;
        const bool we_initiate = !is_peer_inbound && is_peer_recon_responder;

        // If we ever announce support for both requesting and responding, this will need
        // tie-breaking. For now, this is mutually exclusive because both are based on the
        // inbound flag.
        assert(!(they_initiate && we_initiate));

        // The peer set both flags to false, we treat it as a protocol violation.
        if (!(they_initiate || we_initiate)) return PROTOCOL_VIOLATION;

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Register peer=%d with the following params: " /* Continued */
                                                                    "we_initiate=%i, they_initiate=%i.\n",
                      peer_id, we_initiate, they_initiate);

        const uint256 full_salt{ComputeSalt(*local_salt, remote_salt)};
        recon_state->second = TxReconciliationState(we_initiate, full_salt.GetUint64(0), full_salt.GetUint64(1));
        return SUCCESS;
    }

    void AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        assert(txs_to_reconcile.size() > 0);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        size_t added = 0;
        for (auto& wtxid: txs_to_reconcile) {
            if (recon_state.m_local_set.insert(wtxid).second) {
                ++added;
            }
        }

        LogPrint(BCLog::NET, "Added %i new transactions to the reconciliation set for peer=%d. " /* Continued */
            "Now the set contains %i transactions.\n", added, peer_id, recon_state.m_local_set.size());
    }

    void TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        recon_state.m_local_set.erase(wtxid_to_remove);
    }

    void ForgetPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (m_states.erase(peer_id)) {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Forget txreconciliation state of peer=%d\n", peer_id);
        }
    }

    bool IsPeerRegistered(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);
        return (recon_state != m_states.end() &&
                std::holds_alternative<TxReconciliationState>(recon_state->second));
    }

    bool ShouldFloodTo(uint256 wtxid, NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        if (!IsPeerRegistered(peer_id)) return true;
        LOCK(m_txreconciliation_mutex);
        const auto recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        // We assume that reconciliation is always initiated from inbound to outbound to avoid
        // code complexity.
        std::vector<NodeId> eligible_peers;

        const bool we_initiate = recon_state.m_we_initiate;
        // Find all peers of the similar reconciliation direction.
        std::for_each(m_states.begin(), m_states.end(),
            [&eligible_peers, we_initiate](std::pair<NodeId, std::variant<uint64_t, TxReconciliationState>> indexed_state) {
                const auto cur_state = std::get<TxReconciliationState>(indexed_state.second);
                if (cur_state.m_we_initiate == we_initiate) eligible_peers.push_back(indexed_state.first);
            }
        );

        // TODO: there should be a cleaner way to do this.
        size_t flood_index_modulo;
        if (we_initiate) {
            flood_index_modulo = 1.0 / OUTBOUND_FANOUT_DESTINATIONS_FRACTION;
        } else {
            flood_index_modulo = 1.0 / INBOUND_FANOUT_DESTINATIONS_FRACTION;
        }

        const auto it = std::find(eligible_peers.begin(), eligible_peers.end(), peer_id);
        assert(it != eligible_peers.end());

        const size_t peer_index = it - eligible_peers.begin();
        return txidHasher(wtxid) % flood_index_modulo == peer_index % flood_index_modulo;
    }
};

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    return m_impl->PreRegisterPeer(peer_id);
}

ReconciliationRegisterResult TxReconciliationTracker::RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                                          bool is_peer_recon_initiator, bool is_peer_recon_responder,
                                                          uint32_t peer_recon_version, uint64_t remote_salt)
{
    return m_impl->RegisterPeer(peer_id, is_peer_inbound, is_peer_recon_initiator, is_peer_recon_responder,
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

bool TxReconciliationTracker::ShouldFloodTo(uint256 wtxid, NodeId peer_id) const
{
    return m_impl->ShouldFloodTo(wtxid, peer_id);
}
