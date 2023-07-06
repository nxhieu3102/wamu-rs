//! Identity rotation implementation.
//!
//! Ref: <https://wamu.tech/specification#identity-rotation>.

use crypto_bigint::U256;

use crate::crypto::VerifyingKey;
use crate::errors::{Error, IdentityAuthedRequestError};
use crate::payloads::{IdentityAuthedRequestPayload, IdentityRotationChallengeResponsePayload};
use crate::sub_share::{SigningShare, SubShare};
use crate::traits::IdentityProvider;
use crate::{identity_authed_request, identity_challenge, share_split_reconstruct, wrappers};

const IDENTITY_ROTATION: &str = "identity-rotation";

/// Given an identity provider, returns the payload for initiating an identity rotation request.
pub fn initiate(identity_provider: &impl IdentityProvider) -> IdentityAuthedRequestPayload {
    identity_authed_request::initiate(IDENTITY_ROTATION, identity_provider)
}

/// Given an identity rotation request payload and a list of verifying keys for the other parties,
/// returns an ok result with a challenge fragment for initiating an identity challenge for a valid request
/// or an appropriate error result for an invalid request.
pub fn verify_request_and_initiate_challenge(
    request: &IdentityAuthedRequestPayload,
    verified_parties: &[VerifyingKey],
) -> Result<U256, IdentityAuthedRequestError> {
    wrappers::verify_identity_authed_request_and_initiate_challenge(
        IDENTITY_ROTATION,
        request,
        verified_parties,
    )
}

/// Given a list of identity challenge fragments, the current identity provider and the new identity provider,
/// returns the identity rotation challenge response payload that includes the new verifying key and
/// challenge response signatures from both the current and the new identity providers.
pub fn challenge_response(
    challenge_fragments: &[U256],
    current_identity_provider: &impl IdentityProvider,
    new_identity_provider: &impl IdentityProvider,
) -> IdentityRotationChallengeResponsePayload {
    IdentityRotationChallengeResponsePayload {
        new_verifying_key: new_identity_provider.verifying_key(),
        current_signature: identity_challenge::respond(
            challenge_fragments,
            current_identity_provider,
        ),
        new_signature: identity_challenge::respond(challenge_fragments, new_identity_provider),
    }
}

/// Given an identity rotation challenge response, a list of identity challenge fragments and
/// a verifying key for challenged party,
/// returns an `Ok` result for valid identity rotation challenge response signature, or an appropriate `Err` result otherwise.
pub fn verify_challenge_response(
    response: &IdentityRotationChallengeResponsePayload,
    challenge_fragments: &[U256],
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    // Verifies current identity.
    identity_challenge::verify(
        &response.current_signature,
        challenge_fragments,
        verifying_key,
    )?;
    // Verifies new identity.
    Ok(identity_challenge::verify(
        &response.new_signature,
        challenge_fragments,
        &response.new_verifying_key,
    )?)
}

/// Given the current "signing share", "sub-share" and identity provider, and the new identity provider,
/// returns the new "signing share" and "sub-share" associated with the new identity provider,
/// that can be used to reconstruct the current "secret share" given the new identity provider.
pub fn rotate_signing_and_sub_share(
    signing_share: &SigningShare,
    sub_share_b: &SubShare,
    current_identity_provider: &impl IdentityProvider,
    new_identity_provider: &impl IdentityProvider,
) -> (SigningShare, SubShare) {
    let secret_share =
        share_split_reconstruct::reconstruct(signing_share, sub_share_b, current_identity_provider);
    share_split_reconstruct::split(secret_share, new_identity_provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::errors::CryptoError;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn identity_rotation_works() {
        // Generates current identity provider.
        let current_identity_provider = MockECDSAIdentityProvider::new();

        // Generate secret share.
        let secret_share = crypto::random_mod();

        // Computes "signing share" and "sub-share".
        let (current_signing_share, current_sub_share_b) =
            share_split_reconstruct::split(secret_share, &current_identity_provider);

        // Generates new identity provider.
        let new_identity_provider = MockECDSAIdentityProvider::new();

        // Generates identity rotation request payload.
        let init_payload = initiate(&current_identity_provider);

        // Verifies identity rotation request and initiates challenge.
        let init_results: Vec<Result<U256, IdentityAuthedRequestError>> = (0..5)
            .map(|_| {
                verify_request_and_initiate_challenge(
                    &init_payload,
                    &[current_identity_provider.verifying_key()],
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
                &current_identity_provider,
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
                &current_identity_provider,
                &(0..3u8).map(U256::from).collect(),
                &challenge_fragments,
                Err(Error::Crypto(CryptoError::InvalidSignature)),
            ),
        ] {
            // Generates identity rotation challenge response using the "actual signer" and "signing challenge fragments" for this test case.
            let challenge_payload = challenge_response(
                fragments_to_sign,
                actual_current_signer,
                &new_identity_provider,
            );

            // Verifies identity rotation challenge response using the challenged identity provider and "verification challenge fragments" for this test case.
            let challenge_result = verify_challenge_response(
                &challenge_payload,
                fragments_to_verify,
                &current_identity_provider.verifying_key(),
            );

            // Verifies expected result.
            assert_eq!(challenge_result, expected_challenge_result);
        }

        // Computes the new "signing share" and "sub-share".
        let (new_signing_share, new_sub_share_b) = rotate_signing_and_sub_share(
            &current_signing_share,
            &current_sub_share_b,
            &current_identity_provider,
            &new_identity_provider,
        );

        // Reconstructs "secret share" from new "signing share", "sub-share" and identity provider.
        let reconstructed_secret_share = share_split_reconstruct::reconstruct(
            &new_signing_share,
            &new_sub_share_b,
            &new_identity_provider,
        );

        // Verifies reconstructed "secret share".
        assert_eq!(&reconstructed_secret_share, &secret_share);
    }
}
