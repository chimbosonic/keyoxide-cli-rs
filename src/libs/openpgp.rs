use super::{
    clap::PrintFormat,
    doip::{verify_proof, VerifiedProof},
};
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::keys::openpgp::get_keys_doip_proofs;
use futures::future::join_all;
use miette::Result;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;
use serde::Serialize;

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct KeyVerifiedProofs {
    fingerprint: String,
    proof_uri: String,
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

impl KeyVerifiedProofs {
    pub async fn new(cert: Cert) -> Result<Self> {
        #[allow(clippy::mutable_key_type)]
        let doip_proofs = get_keys_doip_proofs(&cert)?;

        let mut key_verified_proofs = KeyVerifiedProofs {
            fingerprint: cert.fingerprint().to_hex(),
            proof_uri: format!("openpgp4fpr:{}", cert.fingerprint().to_hex()),
            userid_proofs: Vec::new(),
        };

        for (user_id, proofs) in doip_proofs {
            let user_id_string = user_id_to_user_id_string(user_id);

            let mut proofs_futures = Vec::new();

            for service_uri in proofs {
                let verification_result =
                    verify_proof(service_uri, key_verified_proofs.proof_uri.clone());
                proofs_futures.push(verification_result);
            }

            let proofs = join_all(proofs_futures)
                .await
                .into_iter()
                .map(|(s, r)| VerifiedProof::new(s, r))
                .collect();

            let mut verified_proofs = UserIDVerifiedProofs::new(user_id_string);
            verified_proofs.proofs = proofs;
            key_verified_proofs.add_userid_proofs(verified_proofs);
        }
        Ok(key_verified_proofs)
    }

    fn add_userid_proofs(&mut self, proofs: UserIDVerifiedProofs) {
        self.userid_proofs.push(proofs)
    }

    pub fn print(&self, print_format: &PrintFormat) {
        match print_format {
            PrintFormat::Json => println!("{self}"),
            PrintFormat::JsonPretty => println!("{self:?}"),
            PrintFormat::Text => {
                let mut print = String::new();
                print.push_str(format!("OpenPGP Key Fingerprint: {}\n", self.fingerprint).as_str());

                for useridproofs in &self.userid_proofs {
                    print.push_str(format!("  UserID: {}\n", useridproofs.userid).as_str());

                    for verified_proof in &useridproofs.proofs {
                        if verified_proof.verification_result.is_some() {
                            print.push_str(format!("    {}: ✅\n", verified_proof.uri).as_str());
                        } else {
                            print.push_str(format!("    {}: ❌\n", verified_proof.uri).as_str());
                        }
                    }
                }

                print!("{}", print);
            }
        }
    }
}

fn user_id_to_user_id_string(user_id: UserID) -> String {
    let user_id_name = user_id.name2().unwrap_or(None).unwrap_or("");
    let user_id_email = user_id.email2().unwrap_or(None).unwrap_or("");
    format!("{user_id_name} <{user_id_email}>")
}
