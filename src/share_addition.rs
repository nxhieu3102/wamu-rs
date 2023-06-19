//! Share addition implementation.
//!
//! Ref: <https://wamu.tech/specification#share-addition>.

use crate::crypto::VerifyingKey;
use crate::errors::IdentityAuthedRequestError;
use crate::errors::QuorumApprovedRequestError;
use crate::identity_provider::IdentityProvider;
use crate::payloads::{
    CommandApprovalPayload, IdentityAuthedRequestPayload, QuorumApprovedChallengeResponsePayload,
};
use crate::quorum_approved_request;

const SHARE_ADDITION: &str = "share-addition";

/// Given an identity provider, returns the payload for initiating an quorum approved request.
pub fn initiate(identity_provider: &impl IdentityProvider) -> IdentityAuthedRequestPayload {
    quorum_approved_request::initiate(SHARE_ADDITION, identity_provider)
}

/// Given a share addition request payload, an identity provider and a list of verifying keys for the other parties,
/// returns an ok result with a share addition approval payload for initiating an identity challenge and approval acknowledgement for a valid request
/// or an appropriate error result for an invalid request.
pub fn verify_request_and_initiate_challenge(
    request: &IdentityAuthedRequestPayload,
    identity_provider: &impl IdentityProvider,
    verified_parties: &[VerifyingKey],
) -> Result<CommandApprovalPayload, IdentityAuthedRequestError> {
    quorum_approved_request::verify_request_and_initiate_challenge(
        SHARE_ADDITION,
        request,
        identity_provider,
        verified_parties,
    )
}

/// Given a list of share addition approval payloads, an identity provider, a share addition request payload,
/// a quorum size and a list of verifying keys for the other parties,
/// returns an ok result with a share addition challenge response payload
/// or an appropriate error result for an invalid request.
pub fn challenge_response(
    approvals: &[CommandApprovalPayload],
    identity_provider: &impl IdentityProvider,
    request: &IdentityAuthedRequestPayload,
    quorum_size: usize,
    verified_parties: &[VerifyingKey],
) -> Result<QuorumApprovedChallengeResponsePayload, QuorumApprovedRequestError> {
    quorum_approved_request::challenge_response(
        approvals,
        identity_provider,
        request,
        quorum_size,
        verified_parties,
    )
}

/// Given a share addition challenge response payload, a list of share addition approval payloads,
/// a verifying key for challenged party, a share addition request payload,
/// a quorum size and a list of verifying keys for the other parties,
/// returns an ok result for a valid share addition challenge response
/// or an appropriate error result for an invalid request.
pub fn verify_challenge_response(
    response: &QuorumApprovedChallengeResponsePayload,
    approvals: &[CommandApprovalPayload],
    verifying_key: &VerifyingKey,
    request: &IdentityAuthedRequestPayload,
    quorum_size: usize,
    verified_parties: &[VerifyingKey],
) -> Result<(), QuorumApprovedRequestError> {
    quorum_approved_request::verify_challenge_response(
        response,
        approvals,
        verifying_key,
        request,
        quorum_size,
        verified_parties,
    )
}
