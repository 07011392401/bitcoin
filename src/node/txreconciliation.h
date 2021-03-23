// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXRECONCILIATION_H
#define BITCOIN_NODE_TXRECONCILIATION_H

#include <net.h>
#include <sync.h>

#include <memory>
#include <tuple>

/**
 * Transaction reconciliation is a way for nodes to efficiently announce transactions.
 * This object keeps track of all reconciliation-related communications with the peers.
 * The high-level protocol is:
 * 0.  Reconciliation protocol handshake.
 * 1.  Once we receive a new transaction, add it to the set instead of announcing immediately.
 * 2.  At regular intervals, a reconciliation initiator requests a sketch from the peer, where a
 *     sketch is a compressed representation of short form IDs of the transactions in their set.
 * 3.  Once the initiator received a sketch from the peer, the initiator computes a local sketch,
 *     and combines the two sketches to attempt finding the difference in *sets*.
 * 4a. If the difference was not larger than estimated, see SUCCESS below.
 * 4b. If the difference was larger than estimated, initial reconciliation fails. The initiator
 *     requests a larger sketch via an extension round (allowed only once).
 *     - If extension succeeds (a larger sketch is sufficient), see SUCCESS below.
 *     - If extension fails (a larger sketch is insufficient), see FAILURE below.
 *
 * SUCCESS. The initiator knows full symmetrical difference and can request what the initiator is
 *          missing and announce to the peer what the peer is missing.
 *
 * FAILURE. The initiator notifies the peer about the failure and announces all transactions from
 *          the corresponding set. Once the peer received the failure notification, the peer
 *          announces all transactions from their set.

 * This is a modification of the Erlay protocol (https://arxiv.org/abs/1905.10518) with two
 * changes (sketch extensions instead of bisections, and an extra INV exchange round), both
 * are motivated in BIP-330.
 */
class TxReconciliationTracker
{
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxReconciliationTracker(uint32_t recon_version);
    ~TxReconciliationTracker();

    /**
     * Step 0. Generates initial part of the state (salt) required to reconcile with the peer.
     * The salt used for short ID computation required for reconciliation.
     * The function returns the salt.
     * A peer can't participate in future reconciliations without this call.
     * This function must be called only once per peer.
     */
    uint64_t PreRegisterPeer(NodeId peer_id);

    /**
     * Step 0. Once the peer agreed to reconcile with us, generate the state required to track
     * ongoing reconciliations. Should be called only after pre-registering the peer and only once.
     * Returns:
     * - true if the peer was registered
     * - false if the peer violates the protocol
     * - nullopt if nothing was done (e.g., we haven't pre-registered this peer)
     */
    std::optional<bool> RegisterPeer(NodeId peer_id, bool peer_inbound, bool recon_initiator,
                                     bool recon_responder, uint32_t peer_recon_version, uint64_t remote_salt);

    /**
     * Step 1. Add new transactions we want to announce to the peer to the local reconciliation set
     * of the peer, so that those transactions will be reconciled later.
     */
    void AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile);

    /**
     * Before Step 2, we might want to remove a wtxid from the reconciliation set, for example if
     * the peer just announced the transaction to us.
     */
    void TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove);

    /**
     * Step 2. If a it's time to request a reconciliation from the peer, this function will return
     * the details of our local state, which should be communicated to the peer so that they better
     * know what we need:
     * - size of our reconciliation set for the peer
     * - our q-coefficient with the peer, formatted to be transmitted as integer value
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(NodeId peer_id);

    /**
     * Attempts to forget reconciliation-related state of the peer (if we previously stored any).
     * After this, we won't be able to reconcile with the peer.
     */
    void ForgetPeer(NodeId peer_id);

    /**
     * Check if a peer is registered to reconcile with us.
     */
    bool IsPeerRegistered(NodeId peer_id) const;

    /**
     * Returns the size of the reconciliation set we have locally for the given peer.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<size_t> GetPeerSetSize(NodeId peer_id) const;

    /**
     * Returns whether for the given call the peer is chosen as a low-fanout destination.
     */
    bool ShouldFloodTo(uint256 wtxid, NodeId peer_id) const;

    /**
     * Check whether a particular transaction is being currently reconciled with a given peer.
     */
    bool CurrentlyReconcilingTx(NodeId peer_id, const uint256 wtxid) const;
};

#endif // BITCOIN_NODE_TXRECONCILIATION_H
