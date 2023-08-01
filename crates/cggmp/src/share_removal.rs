//! Share removal implementation.
//!
//! Ref: <https://wamu.tech/specification#share-removal>.

use curv::elliptic::curves::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use round_based::{Msg, StateMachine};
use std::collections::HashMap;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::{IdentityProvider, SigningShare, SubShare};

use crate::authorized_key_refresh::{AuthorizedKeyRefresh, AuthorizedKeyRefreshMessage, Error};
use crate::key_refresh::AugmentedKeyRefresh;
use crate::quorum_approval;
use crate::quorum_approval::QuorumApproval;

const SHARE_REMOVAL: &str = "share-removal";

/// A [StateMachine](StateMachine) that implements [share removal as described by the Wamu protocol](https://wamu.tech/specification#share-removal).
pub struct ShareRemoval<'a, I: IdentityProvider> {
    // Quorum approval.
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// Party index.
    idx: u16,
    /// Total number of parties.
    n_parties: u16,

    // Key refresh.
    /// The "signing share" of the party
    /// (only `None` for the new parties, `Some` for all other parties).
    signing_share: &'a SigningShare,
    /// The "sub-share" of the party
    /// (only `None` for the new party, `Some` for all other parties).
    sub_share: &'a SubShare,
    /// Local key of the party (with secret share cleared/zerorized).
    local_key: LocalKey<Secp256k1>,
    /// Maps existing indices to new ones for refreshing parties.
    old_to_new_map: &'a HashMap<u16, u16>,

    // State machine management.
    /// Outgoing message queue.
    message_queue: Vec<Msg<AuthorizedKeyRefreshMessage<'a, I, quorum_approval::Message>>>,
    /// Quorum approval state machine (must succeed before key refresh is performed).
    init_state_machine: QuorumApproval<'a, I>,
    /// Key refresh state machine (activated after successful quorum approval).
    refresh_state_machine: Option<AugmentedKeyRefresh<'a, I>>,
    /// Stores "out of order" messages.
    out_of_order_buffer: Vec<Msg<AuthorizedKeyRefreshMessage<'a, I, quorum_approval::Message>>>,
}

impl<'a, I: IdentityProvider> ShareRemoval<'a, I> {
    /// Initializes party for the share removal protocol.
    pub fn new(
        signing_share: &'a SigningShare,
        sub_share: &'a SubShare,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        // `LocalKey<Secp256k1>` with secret share set to zero.
        local_key: LocalKey<Secp256k1>,
        n_parties: u16,
        old_to_new_map: &'a HashMap<u16, u16>,
        is_initiator: bool,
    ) -> Result<ShareRemoval<'a, I>, Error<'a, I, <QuorumApproval<'a, I> as StateMachine>::Err>>
    {
        // Initializes quorum approval state machine.
        let init_state_machine = QuorumApproval::new(
            SHARE_REMOVAL,
            identity_provider,
            verified_parties,
            local_key.i,
            local_key.t,
            local_key.n,
            is_initiator,
            false,
        );

        // Initializes share removal state machine.
        let mut share_removal = Self {
            // Quorum approval.
            identity_provider,
            verified_parties,
            idx: local_key.i,
            n_parties,
            // Key refresh.
            signing_share,
            sub_share,
            local_key,
            old_to_new_map,
            // State machine management.
            message_queue: Vec::new(),
            init_state_machine,
            refresh_state_machine: None,
            out_of_order_buffer: Vec::new(),
        };

        // Retrieves messages from immediate state transitions (if any) and wraps them.
        share_removal.update_composite_message_queue()?;

        // Returns share removal machine.
        Ok(share_removal)
    }
}

impl<'a, I: IdentityProvider> AuthorizedKeyRefresh<'a, I> for ShareRemoval<'a, I> {
    type InitStateMachineType = QuorumApproval<'a, I>;

    impl_required_authorized_key_refresh_getters!(
        init_state_machine,
        refresh_state_machine,
        message_queue,
        out_of_order_buffer
    );

    fn create_key_refresh(
        &mut self,
    ) -> Result<
        AugmentedKeyRefresh<'a, I>,
        Error<'a, I, <Self::InitStateMachineType as StateMachine>::Err>,
    > {
        // Initializes key refresh state machine.
        Ok(AugmentedKeyRefresh::new(
            Some(self.signing_share),
            Some(self.sub_share),
            self.identity_provider,
            self.verified_parties,
            Some(self.local_key.clone()),
            None,
            self.old_to_new_map,
            self.local_key.t,
            self.n_parties,
            None,
        )?)
    }
}

impl_state_machine_for_authorized_key_refresh!(ShareRemoval, idx, n_parties);

// Implement `Debug` trait for `ShareRemoval` for test simulations.
#[cfg(test)]
impl<'a, I: IdentityProvider> std::fmt::Debug for ShareRemoval<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share Addition")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aug_state_machine::{AugmentedType, SubShareOutput};
    use crate::keygen::tests::simulate_key_gen;
    use curv::elliptic::curves::Scalar;
    use round_based::dev::Simulation;

    pub fn simulate_share_removal(
        // Party key configs including the "signing share", "sub-share", identity provider and
        // `LocalKey<Secp256k1>` from `multi-party-ecdsa` with the secret share cleared/zerorized.
        party_key_configs: Vec<(
            &SigningShare,
            &SubShare,
            &impl IdentityProvider,
            LocalKey<Secp256k1>,
            bool, // Whether or not this party is the initiator.
        )>,
        current_to_new_idx_map: &HashMap<u16, u16>,
        n_parties: u16,
    ) -> Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = party_key_configs
            .iter()
            .map(|(_, _, identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (signing_share, sub_share, identity_provider, local_key, is_initiator) in
            party_key_configs
        {
            simulation.add_party(
                ShareRemoval::new(
                    signing_share,
                    sub_share,
                    identity_provider,
                    &verifying_keys,
                    local_key,
                    n_parties,
                    current_to_new_idx_map,
                    is_initiator,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    #[test]
    fn share_removal_works() {
        let threshold = 2;
        let n_parties_init = 5;
        let n_parties_new = 4;
        let initiating_party_idx = 2u16;

        // Verifies parameter invariants.
        assert!(threshold >= 1, "minimum threshold is one");
        assert!(
            n_parties_init > threshold,
            "threshold must be less than the total number of parties"
        );
        assert!(
            n_parties_new > threshold,
            "threshold must be less than the total number of parties"
        );
        assert!(
            n_parties_new < n_parties_init,
            "`n_parties_new` must be less than `n_parties_init`"
        );

        // Runs key gen simulation for test parameters.
        let (mut aug_keys, mut identity_providers) = simulate_key_gen(threshold, n_parties_init);
        // Verifies that we got enough keys and identities for "existing" parties from keygen.
        assert_eq!(aug_keys.len(), identity_providers.len());
        assert_eq!(aug_keys.len(), n_parties_init as usize);

        // Keep copy of current public key for later verification.
        let pub_key_init = aug_keys[0].base.public_key();

        // Removes some existing parties.
        if n_parties_new < n_parties_init {
            aug_keys.truncate(n_parties_new as usize);
            identity_providers.truncate(n_parties_new as usize);
        }

        // Creates key configs and party indices for continuing/existing parties.
        let mut party_key_configs = Vec::new();
        let mut current_to_new_idx_map = HashMap::new();
        for (i, key) in aug_keys.iter().enumerate() {
            // Create party key config and index entry.
            let idx = i as u16 + 1;
            let (signing_share, sub_share) = key.extra.as_ref().unwrap();
            let local_key = key.base.clone();
            current_to_new_idx_map.insert(local_key.i, idx);
            party_key_configs.push((
                signing_share,
                sub_share,
                &identity_providers[i],
                local_key,
                idx == initiating_party_idx,
            ));
        }

        // Runs share removal simulation for test parameters.
        let new_keys =
            simulate_share_removal(party_key_configs, &current_to_new_idx_map, n_parties_new);

        // Verifies the refreshed/generated keys and configuration for all parties.
        assert_eq!(new_keys.len(), n_parties_new as usize);
        for (i, new_key) in new_keys.iter().enumerate() {
            // Verifies threshold and number of parties.
            assert_eq!(new_key.base.t, threshold);
            assert_eq!(new_key.base.n, n_parties_new);
            // Verifies that the secret share was cleared/zerorized.
            assert_eq!(new_key.base.keys_linear.x_i, Scalar::<Secp256k1>::zero());
            // Verifies that the public key hasn't changed.
            assert_eq!(new_key.base.public_key(), pub_key_init);
            // Verifies that the "signing share" and "sub-share" have changed for existing/continuing parties.
            if let Some(prev_key) = aug_keys.get(i) {
                let (prev_signing_share, prev_sub_share) = prev_key.extra.as_ref().unwrap();
                let (new_signing_share, new_sub_share) = new_key.extra.as_ref().unwrap();
                assert_ne!(
                    new_signing_share.to_be_bytes(),
                    prev_signing_share.to_be_bytes()
                );
                assert_ne!(new_sub_share.as_tuple(), prev_sub_share.as_tuple());
            }
        }
    }
}
