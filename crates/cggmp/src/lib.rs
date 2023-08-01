//! A Rust implementation of [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification) for building threshold signature wallets controlled by multiple decentralized identities.

pub use self::{
    errors::Error, identity_auth::IdentityAuthentication, identity_rotation::IdentityRotation,
    key_refresh::AugmentedKeyRefresh, keygen::AugmentedKeyGen, quorum_approval::QuorumApproval,
    share_addition::ShareAddition, share_recovery_quorum::ShareRecoveryQuorum,
    share_removal::ShareRemoval, sign::AugmentedPreSigning, sign::AugmentedSigning,
    threshold_modification::ThresholdModification,
};

#[macro_use]
pub mod aug_state_machine;
#[macro_use]
mod authorized_key_refresh;
mod errors;
mod identity_auth;
mod identity_rotation;
mod key_refresh;
mod keygen;
mod quorum_approval;
mod share_addition;
mod share_recovery_quorum;
mod share_removal;
mod sign;
mod threshold_modification;
