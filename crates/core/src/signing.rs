//! Signing implementation.
//!
//! Ref: <https://wamu.tech/specification#signing>.

use crate::crypto::{Signature, VerifyingKey};
use crate::errors::Error;
use crate::identity_provider::IdentityProvider;
use crate::wrappers;

/// Given a message and an identity provider, returns the verifying key and a signature of the message.
pub fn initiate(
    message: &[u8],
    identity_provider: &impl IdentityProvider,
) -> (VerifyingKey, Signature) {
    wrappers::initiate_request_with_signature(message, identity_provider)
}

/// Given a message, a verifying key for the sending party, a signature of the message and
/// a list of verifying keys for the other parties,
/// returns an ok result for a valid request or an appropriate error result for an invalid request.
pub fn verify(
    message: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
    verified_parties: &[VerifyingKey],
) -> Result<(), Error> {
    wrappers::verify_request_with_signature(message, verifying_key, signature, verified_parties)
}
