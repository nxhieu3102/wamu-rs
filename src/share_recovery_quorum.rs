//! Share recovery with quorum implementation.
//!
//! Ref: <https://wamu.tech/specification#share-recovery-quorum>.

use crypto_bigint::U256;

use crate::crypto::{Signature, VerifyingKey};
use crate::errors::{Error, IdentityAuthedRequestError};
use crate::identity_provider::IdentityProvider;
use crate::payloads::IdentityAuthedRequestPayload;
use crate::{identity_authed_request, identity_challenge, wrappers};

const SHARE_RECOVERY: &str = "share-recovery";

/// Given an identity provider, returns the payload for initiating a share recovery request.
pub fn initiate(identity_provider: &impl IdentityProvider) -> IdentityAuthedRequestPayload {
    identity_authed_request::initiate(SHARE_RECOVERY, identity_provider)
}

/// Given a share recovery request payload and a list of verifying keys for the other parties,
/// returns an ok result with a challenge fragment for initiating an identity challenge for a valid request
/// or an appropriate error result for an invalid request.
pub fn verify_request_and_initiate_challenge(
    request: &IdentityAuthedRequestPayload,
    verified_parties: &[VerifyingKey],
) -> Result<U256, IdentityAuthedRequestError> {
    wrappers::verify_authed_request_and_initiate_challenge(
        SHARE_RECOVERY,
        request,
        verified_parties,
    )
}

/// Given a list of identity challenge fragments and an identity provider,
/// returns the response signature for an identity challenge.
pub fn challenge_response(
    challenge_fragments: &[U256],
    identity_provider: &impl IdentityProvider,
) -> Signature {
    identity_challenge::respond(challenge_fragments, identity_provider)
}

/// Given a share recovery challenge response signature, a list of identity challenge fragments and
/// a verifying key for challenged party,
/// returns an `Ok` result for valid share recovery challenge response signature, or an appropriate `Err` result otherwise.
pub fn verify_challenge_response(
    signature: &Signature,
    challenge_fragments: &[U256],
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    Ok(identity_challenge::verify(
        signature,
        challenge_fragments,
        verifying_key,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CryptoError;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn share_recovery_with_quorum_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::new();

        // Generates share recovery request payload.
        let init_payload = initiate(&identity_provider);

        // Verifies share recovery request and initiates challenge.
        let init_results: Vec<Result<U256, IdentityAuthedRequestError>> = (0..5)
            .map(|_| {
                verify_request_and_initiate_challenge(
                    &init_payload,
                    &[identity_provider.verifying_key()],
                )
            })
            .collect();

        // Verifies expected result.
        assert!(!init_results.iter().any(|result| result.is_err()));

        // Unwrap challenge fragments.
        let challenge_fragments: Vec<U256> = init_results
            .into_iter()
            .map(|result| result.unwrap())
            .collect();

        for (
            actual_current_signer,
            fragments_to_sign,
            fragments_to_verify,
            expected_challenge_result,
        ) in [
            // Valid challenge response should be accepted.
            (
                &identity_provider,
                &challenge_fragments,
                &challenge_fragments,
                Ok(()),
            ),
            // Challenge response from the wrong signer should be rejected.
            (
                &MockECDSAIdentityProvider::new(),
                &challenge_fragments,
                &challenge_fragments,
                Err(Error::Crypto(CryptoError::InvalidSignature)),
            ),
            // Challenge response signing the wrong challenge fragments should be rejected.
            (
                &identity_provider,
                &(0..3u8).map(U256::from).collect(),
                &challenge_fragments,
                Err(Error::Crypto(CryptoError::InvalidSignature)),
            ),
        ] {
            // Generates share recovery challenge response using the "actual signer" and "signing challenge fragments" for this test case.
            let challenge_payload = challenge_response(fragments_to_sign, actual_current_signer);

            // Verifies share recovery challenge response using the challenged identity provider and "verification challenge fragments" for this test case.
            let challenge_result = verify_challenge_response(
                &challenge_payload,
                fragments_to_verify,
                &identity_provider.verifying_key(),
            );

            // Verifies expected result.
            assert_eq!(challenge_result, expected_challenge_result);
        }
    }
}
