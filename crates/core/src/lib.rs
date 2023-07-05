//! A Rust implementation of the [Wamu protocol](https://wamu.tech/specification) for building threshold signature wallets controlled by multiple decentralized identities.

pub use self::{
    errors::{
        CryptoError, Error, IdentityAuthedRequestError, QuorumApprovedRequestError,
        ShareBackupRecoveryError,
    },
    identity_provider::IdentityProvider,
    payloads::{
        CommandApprovalPayload, EncryptedShareBackup, IdentityAuthedRequestPayload,
        IdentityRotationChallengeResponsePayload, QuorumApprovedChallengeResponsePayload,
    },
    sub_share::{SigningShare, SubShare},
};

mod crypto;
mod errors;
pub mod identity_authed_request;
pub mod identity_challenge;
mod identity_provider;
pub mod identity_rotation;
pub mod key_generation;
pub mod key_refresh;
mod payloads;
pub mod quorum_approved_request;
pub mod share_addition;
pub mod share_recovery_backup;
pub mod share_recovery_quorum;
pub mod share_removal;
pub mod share_split_reconstruct;
pub mod signing;
mod sub_share;
mod test_utils;
pub mod threshold_modification;
mod utils;
mod wrappers;
