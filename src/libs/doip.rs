use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::{
    claim::{Claim, VerificationResult},
    service_provider::SPAbout,
};
use serde::Serialize;

use super::error::ProofError;

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct VerifiedProof {
    pub uri: String,
    pub verification_result: Option<AppVerificationResult>,
}

impl VerifiedProof {
    pub fn new(proof: String, verification_result: Option<VerificationResult>) -> VerifiedProof {
        VerifiedProof {
            uri: proof,
            verification_result: verification_result.map(AppVerificationResult::from),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AppVerificationResult {
    result: bool,
    service_provider_info: Option<SPAbout>,
    proxy_used: Option<String>,
}

impl From<VerificationResult> for AppVerificationResult {
    fn from(verification_result: VerificationResult) -> Self {
        AppVerificationResult {
            result: verification_result.result,
            service_provider_info: match verification_result.service_provider {
                Some(service_provier) => Some(service_provier.about),
                None => None,
            },
            proxy_used: verification_result.proxy_used,
        }
    }
}

pub async fn verify_proof(
    service_uri: String,
    proof_uri: String,
) -> (String, Option<VerificationResult>) {
    let claim = Claim::new(service_uri.to_string(), proof_uri.to_string());
    match claim.find_matches() {
        Ok(matches) => (
            service_uri.to_string(),
            claim
                .verify_with_matches(matches)
                .await
                .map_err(|error| {
                    ProofError::from(proof_uri.to_string(), service_uri.to_string(), error)
                        .warn_proof_errors();
                    None::<VerificationResult>
                })
                .ok(),
        ),
        Err(error) => {
            ProofError::from(proof_uri.to_string(), service_uri.to_string(), error)
                .warn_proof_errors();
            (service_uri.to_string(), None)
        }
    }
}
