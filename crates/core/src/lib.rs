//! A Rust implementation of the core [Wamu protocol](https://wamu.tech/specification) for building [threshold signature](https://academy.binance.com/en/articles/threshold-signatures-explained) wallets controlled by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/).

pub use self::{
    errors::{
        CryptoError, Error, IdentityAuthedRequestError, QuorumApprovedRequestError,
        ShareBackupRecoveryError,
    },
    payloads::{
        CommandApprovalPayload, EncryptedShareBackup, IdentityAuthedRequestPayload,
        IdentityRotationChallengeResponsePayload, QuorumApprovedChallengeResponsePayload,
    },
    share::{SecretShare, SigningShare, SubShare},
    traits::IdentityProvider,
};

pub mod crypto;
mod errors;
pub mod identity_authed_request;
pub mod identity_challenge;
pub mod identity_rotation;
mod payloads;
pub mod quorum_approved_request;
mod share;
pub mod share_recovery_backup;
pub mod share_split_reconstruct;
mod test_utils;
mod traits;
mod utils;
pub mod wrappers;
