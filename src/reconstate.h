// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/siphash.h>
#include <minisketch/include/minisketch.h>

#include <chrono>
#include <cmath>
#include <set>
#include <string>
#include <vector>

/** Default coefficient used to estimate set difference for tx reconciliation. */
static constexpr double DEFAULT_RECON_Q = 0.02;
/** Used to convert a floating point reconciliation coefficient q to an int for transmission.
  * Specified by BIP-330.
  */
static constexpr uint16_t Q_PRECISION{(2 << 14) - 1};
/** The size of the field, used to compute sketches to reconcile transactions (see BIP-330). */
static constexpr unsigned int RECON_FIELD_SIZE = 32;
/** Limit sketch capacity to avoid DoS. */
static constexpr uint16_t MAX_SKETCH_CAPACITY = 2 << 12;
/**
* It is possible that if sketch encodes more elements than the capacity, or
* if it is constructed of random bytes, sketch decoding may "succeed",
* but the result will be nonsense (false-positive decoding).
* Given this coef, a false positive probability will be of 1 in 2**coef.
*/
static constexpr unsigned int RECON_FALSE_POSITIVE_COEF = 16;
static_assert(RECON_FALSE_POSITIVE_COEF <= 256,
    "Reducing reconciliation false positives beyond 1 in 2**256 is not supported");

/**
 * Used to keep track of the current reconciliation round with a peer.
 * Used for both inbound (responded) and outgoing (requested/initiated) reconciliations.
 * Currently only one sketch extension request is supported.
 */
enum ReconPhase {
    RECON_NONE,
    RECON_INIT_REQUESTED,
    RECON_INIT_RESPONDED,
    RECON_EXT_REQUESTED,
    RECON_EXT_RESPONDED,
};

/**
 * This struct is used to keep track of the reconciliations with a given peer,
 * and also short transaction IDs for the next reconciliation round.
 * Transaction reconciliation means an efficient synchronization of the known
 * transactions between a pair of peers.
 * One reconciliation round consists of a sequence of messages. The sequence is
 * asymmetrical, there is always a requestor and a responder. At the end of the
 * sequence, nodes are supposed to exchange transactions, so that both of them
 * have all relevant transactions. For more protocol details, refer to BIP-0330.
 */
class ReconState {
    /** Whether this peer will send reconciliation requests. */
    bool m_requestor;

    /** Whether this peer will respond to reconciliation requests. */
    bool m_responder;

    /**
     * Since reconciliation-only approach makes transaction relay
     * significantly slower, we also announce some of the transactions
     * (currently, transactions received from inbound links)
     * to some of the peers:
     * - all pre-reconciliation peers supporting transaction relay;
     * - a limited number of outbound reconciling peers *for which this flag is enabled*.
     * We enable this flag based on whether we have a
     * sufficient number of outbound transaction relay peers.
     * This flooding makes transaction relay across the network faster
     * without introducing high the bandwidth overhead.
     * Transactions announced via flooding should not be added to
     * the reconciliation set.
     */
    bool m_flood_to;

    /**
     * Reconciliation involves computing and transmitting sketches,
     * which is a bandwidth-efficient representation of transaction IDs.
     * Since computing sketches over full txID is too CPU-expensive,
     * they will be computed over shortened IDs instead.
     * These short IDs will be salted so that they are not the same
     * across all pairs of peers, because otherwise it would enable network-wide
     * collisions which may (intentionally or not) halt relay of certain transactions.
     * Both of the peers contribute to the salt.
     */
    const uint64_t m_k0, m_k1;

    /**
     * Computing a set reconciliation sketch involves estimating the difference
     * between sets of transactions on two sides of the connection. More specifically,
     * a sketch capacity is computed as
     * |set_size - local_set_size| + q * (set_size + local_set_size) + c,
     * where c is a small constant, and q is a node+connection-specific coefficient.
     * This coefficient is recomputed by every node based on its previous reconciliations,
     * to better predict future set size differences.
     */
    double m_local_q;

    /**
     * Store all transactions which we would relay to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute an efficient representation of this set ("sketch") and use it to efficient reconcile
     * this set with a similar set on the other side of the connection.
     */
    std::set<uint256> m_local_set;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * This is a cache of these IDs enabling faster lookups of full wtxids,
     * useful when peer will ask for missing transactions by short IDs
     * at the end of a reconciliation round.
     */
    std::map<uint32_t, uint256> m_local_short_id_mapping;

    /**
     * A reconciliation request comes from a peer with a reconciliation set size from their side,
     * which is supposed to help us to estimate set difference size. The value is stored here until
     * we respond to that request with a sketch.
     */
    uint16_t m_remote_set_size;

    /**
     * The use of q coefficients is described above (see local_q comment).
     * The value transmitted from the peer with a reconciliation requests is stored here until
     * we respond to that request with a sketch.
     */
    double m_remote_q;

    /**
     * When a reconciliation request is received, instead of responding to it right away,
     * we schedule a response for later, so that a spy can’t monitor our reconciliation sets.
     */
    std::chrono::microseconds m_next_recon_respond{0};

    /** Keep track of reconciliations with the peer. */
    ReconPhase m_outgoing_recon{RECON_NONE};
    ReconPhase m_incoming_recon{RECON_NONE};

    /**
     * A reconciliation round may involve an extension, which is an extra exchange of messages.
     * Since it may happen after a delay (at least network latency), new transactions may come
     * during that time. To avoid mixing old and new transactions, those which are subject for
     * extension of a current reconciliation round are moved to a reconciliation set snapshot
     * after an initial (non-extended) sketch is sent.
     * New transactions are kept in the regular reconciliation set.
     */
    std::set<uint256> m_local_set_snapshot;

    /**
     * A reconciliation round may involve an extension, in which case we should remember
     * a capacity of the sketch sent out initially, so that a sketch extension is of the same size.
     */
    uint16_t m_capacity_snapshot{0};

    /**
     * In a reconciliation round initiated by us, if we asked for an extension, we want to store
     * the sketch computed/transmitted in the initial step, so that we can use it when
     * sketch extension arrives.
     */
    std::vector<uint8_t> m_remote_sketch_snapshot;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * Short IDs are salted with a link-specific constant value.
     */
    uint32_t ComputeShortID(const uint256 wtxid) const
    {
        const uint64_t s = SipHashUint256(m_k0, m_k1, wtxid);
        const uint32_t short_txid = 1 + (s & 0xFFFFFFFF);
        return short_txid;
    }

    /**
     * Reconciliation involves computing a space-efficient representation of transaction identifiers
     * (a sketch). A sketch has a capacity meaning it allows reconciling at most a certain number
     * of elements (see BIP-330). Considering whether we are going to send a sketch to a peer or use
     * locally, we estimate the set difference.
     */
    Minisketch ComputeSketch(uint16_t capacity, bool use_snapshot=false)
    {
        Minisketch sketch;
        std::set<uint256> working_set;
        if (use_snapshot) {
            working_set = m_local_set_snapshot;
        } else {
            working_set = m_local_set;
            m_capacity_snapshot = capacity;
        }
        // Avoid serializing/sending an empty sketch.
        if (working_set.size() == 0 || capacity == 0) return sketch;

        std::vector<uint32_t> short_ids;
        for (const auto& wtxid: working_set) {
            uint32_t short_txid = ComputeShortID(wtxid);
            short_ids.push_back(short_txid);
            m_local_short_id_mapping.emplace(short_txid, wtxid);
        }

        capacity = std::min(capacity, MAX_SKETCH_CAPACITY);
        sketch = Minisketch(RECON_FIELD_SIZE, 0, capacity);
        if (sketch) {
            for (const uint32_t short_id: short_ids) {
                sketch.Add(short_id);
            }
        }
        return sketch;
    }

    void ClearState()
    {
        m_local_short_id_mapping.clear();
        // This is currently belt-and-suspenders, as the code should work even without these calls.
        m_remote_sketch_snapshot.clear();
        m_local_set_snapshot.clear();
        m_capacity_snapshot = 0;
    }

public:

    ReconState(bool requestor, bool responder, bool flood_to, uint64_t k0, uint64_t k1) :
        m_requestor(requestor), m_responder(responder), m_flood_to(flood_to),
        m_k0(k0), m_k1(k1), m_local_q(DEFAULT_RECON_Q) {}

    bool IsChosenForFlooding() const
    {
        return m_flood_to;
    }

    bool IsRequestor() const
    {
        return m_requestor;
    }

    bool IsResponder() const
    {
        return m_responder;
    }

    uint16_t GetLocalSetSize(bool snapshot=false) const
    {
        if (snapshot) return m_local_set_snapshot.size();
        return m_local_set.size();
    }

    uint16_t GetLocalQ() const
    {
        return m_local_q * Q_PRECISION;
    }

    uint16_t GetCapacitySnapshot() const
    {
        return m_capacity_snapshot;
    }

    ReconPhase GetIncomingPhase() const
    {
        return m_incoming_recon;
    }

    ReconPhase GetOutgoingPhase() const
    {
        return m_outgoing_recon;
    }

    std::chrono::microseconds GetNextRespond() const
    {
        return m_next_recon_respond;
    }

    std::vector<uint8_t> GetRemoteSketchSnapshot() const
    {
        return m_remote_sketch_snapshot;
    }

    void AddToReconSet(const std::vector<uint256>& txs_to_reconcile)
    {
        for (const auto& wtxid: txs_to_reconcile) {
            m_local_set.insert(wtxid);
        }
    }

    /**
     * After a reconciliation round passed, transactions missing by our peer are known by short ID.
     * Look up their full wtxid locally to announce them to the peer.
     */
    std::vector<uint256> GetWTXIDsFromShortIDs(const std::vector<uint32_t>& remote_missing_short_ids) const
    {
        std::vector<uint256> remote_missing;
        for (const auto& missing_short_id: remote_missing_short_ids) {
            const auto local_tx = m_local_short_id_mapping.find(missing_short_id);
            if (local_tx != m_local_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            }
        }
        return remote_missing;
    }

    /**
     * When during reconciliation we find a set difference successfully (by combining sketches),
     * we want to find which transactions are missing on our and on their side.
     * For those missing on our side, we may only find short IDs.
     */
    std::pair<std::vector<uint32_t>, std::vector<uint256>> GetRelevantIDsFromShortIDs(const std::vector<uint64_t>& diff) const
    {
        std::vector<uint32_t> local_missing;
        std::vector<uint256> remote_missing;
        for (const auto& diff_short_id: diff) {
            const auto local_tx = m_local_short_id_mapping.find(diff_short_id);
            if (local_tx != m_local_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            } else {
                local_missing.push_back(diff_short_id);
            }
        }
        return std::make_pair(local_missing, remote_missing);
    }

    void PrepareIncoming(uint16_t remote_set_size, double remote_q, std::chrono::microseconds next_respond)
    {
        assert(m_requestor);
        assert(m_incoming_recon == RECON_NONE);
        assert(m_remote_q >= 0 && m_remote_q <= 2);
        m_remote_q = remote_q;
        m_remote_set_size = remote_set_size;
        m_next_recon_respond = next_respond;
    }

    void UpdateIncomingPhase(ReconPhase phase)
    {
        assert(m_requestor);
        m_incoming_recon = phase;
    }

    void UpdateOutgoingPhase(ReconPhase phase)
    {
        assert(m_responder);
        m_outgoing_recon = phase;
    }

    void PrepareForExtensionRequest(uint16_t sketch_capacity)
    {
        // Be ready to respond to extension request, to compute the extended sketch over
        // the same initial set (without transactions received during the reconciliation).
        // Allow to store new transactions separately in the original set.
        assert(m_requestor);
        m_capacity_snapshot = sketch_capacity;
        m_local_set_snapshot = m_local_set;
        m_local_set.clear();
    }

    void PrepareForExtensionResponse(uint16_t sketch_capacity, const std::vector<uint8_t>& remote_sketch)
    {
        assert(m_responder);
        m_capacity_snapshot = sketch_capacity;
        m_remote_sketch_snapshot = remote_sketch;
        m_local_set_snapshot = m_local_set;
        m_local_set.clear();
    }

    std::vector<uint256> GetLocalSet(bool snapshot) const
    {
        if (snapshot) {
            return std::vector<uint256>(m_local_set_snapshot.begin(), m_local_set_snapshot.end());
        } else {
            return std::vector<uint256>(m_local_set.begin(), m_local_set.end());
        }
    }

    Minisketch GetLocalBaseSketch(uint16_t capacity)
    {
        return ComputeSketch(capacity, false);
    }

    Minisketch GetLocalExtendedSketch()
    {
        // For now, compute a sketch of twice the capacity were computed originally.
        // TODO: optimize by computing the extension *on top* of the existent sketch
        // instead of computing the lower order elements again.
        const uint16_t extended_capacity = m_capacity_snapshot * 2;
        return ComputeSketch(extended_capacity, true);
    }

    /**
     * Estimate a capacity of a sketch we will send or use locally (to find set difference)
     * based on the local set size.
     */
    uint16_t EstimateSketchCapacity() const
    {
        const uint16_t set_size_diff = std::abs(uint16_t(m_local_set.size()) - m_remote_set_size);
        const uint16_t min_size = std::min(uint16_t(m_local_set.size()), m_remote_set_size);
        const uint16_t weighted_min_size = m_remote_q * min_size;
        const uint16_t estimated_diff = 1 + weighted_min_size + set_size_diff;
        return minisketch_compute_capacity(RECON_FIELD_SIZE, estimated_diff, RECON_FALSE_POSITIVE_COEF);
    }

    void FinalizeIncomingReconciliation()
    {
        assert(m_requestor);
        ClearState();
    }

    /**
     * Clears the state of the peer when the reconciliation is done.
     * If this is a extension finalization, keep the reconciliation set to track
     * the transactions received from other peers during the reconciliation.
     * Also keep the set if this if finalizing initial incoming reconciliation, because
     * there was a time frame when we sent out an initial sketch until peer responded.
     * If we're finalizing initial outgoing reconciliation, it is safe to clear the set,
     * because we do not use the snapshot, but sketch the original set (which might have received
     * few new transactions), and finalize the reconciliation immediately.
     */
    void FinalizeOutgoingReconciliation(bool clear_local_set, double updated_q)
    {
        assert(m_responder);
        m_local_q = updated_q;
        if (clear_local_set) m_local_set.clear();
        ClearState();
    }
};
