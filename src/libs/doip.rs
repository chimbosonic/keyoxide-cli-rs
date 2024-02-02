use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::{
    claim::{Claim, VerificationResult},
    keys::openpgp::get_keys_doip_proofs,
    service_provider::SPAbout,
};
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;
use serde::Serialize;

use super::error::ProofError;
use miette::Result;

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct KeyVerifiedProofs {
    fingerprint: String,
    userid_proofs: Vec<UserIDVerifiedProofs>,
}

#[derive(Serialize)]
struct UserIDVerifiedProofs {
    userid: String,
    proofs: Vec<VerifiedProof>,
}

impl UserIDVerifiedProofs {
    fn new(userid: String) -> UserIDVerifiedProofs {
        UserIDVerifiedProofs {
            userid,
            proofs: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct VerifiedProof {
    uri: String,
    verification_result: Option<AppVerificationResult>,
}

impl VerifiedProof {
    fn new(proof: String, verification_result: Option<VerificationResult>) -> VerifiedProof {
        VerifiedProof {
            uri: proof,
            verification_result: verification_result.map(AppVerificationResult::from),
        }
    }
}

#[derive(Serialize)]
struct AppVerificationResult {
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

impl KeyVerifiedProofs {
    pub async fn new(cert: Cert) -> Result<Self> {
        #[allow(clippy::mutable_key_type)]
        let doip_proofs = get_keys_doip_proofs(&cert)?;

        let mut key_verified_proofs = KeyVerifiedProofs {
            fingerprint: cert.fingerprint().to_hex(),
            userid_proofs: Vec::new(),
        };

        for (user_id, proofs) in doip_proofs {
            let user_id_string = user_id_to_user_id_string(user_id);
            let mut verified_proofs = UserIDVerifiedProofs::new(user_id_string);

            for proof in proofs {
                let verification_result: Option<VerificationResult> = verify_proof(
                    &proof,
                    &verified_proofs.userid,
                    &key_verified_proofs.get_fingerprint(),
                )
                .await;
                verified_proofs
                    .proofs
                    .push(VerifiedProof::new(proof, verification_result));
            }

            key_verified_proofs.add_userid_proofs(verified_proofs);
            key_verified_proofs.sort_userid_proofs();
        }
        Ok(key_verified_proofs)
    }
    fn sort_userid_proofs(&mut self) {
        self.userid_proofs.sort_by(|a, b| b.userid.cmp(&a.userid));
    }

    fn add_userid_proofs(&mut self, proofs: UserIDVerifiedProofs) {
        self.userid_proofs.push(proofs)
    }

    fn get_fingerprint(&self) -> String {
        self.fingerprint.to_string()
    }

    pub fn print(&self, pretty: bool) {
        if pretty {
            println!("{self:?}");
        } else {
            println!("{self}");
        }
    }
}

async fn verify_proof(proof: &str, userid: &str, fingerprint: &str) -> Option<VerificationResult> {
    let claim = Claim::new(proof.to_string(), fingerprint.to_string());
    match claim.find_matches() {
        Ok(matches) => claim
            .verify_with_matches(matches)
            .await
            .map_err(|error| {
                ProofError::from(proof.to_string(), userid.to_string(), error).warn_proof_errors();
                None::<VerificationResult>
            })
            .ok(),
        Err(error) => {
            ProofError::from(proof.to_string(), userid.to_string(), error).warn_proof_errors();
            None
        }
    }
}

fn user_id_to_user_id_string(user_id: UserID) -> String {
    let user_id_name = user_id.name().unwrap_or(None).unwrap_or("".to_string());
    let user_id_email = user_id.email().unwrap_or(None).unwrap_or("".to_string());
    format!("{user_id_name} <{user_id_email}>")
}
