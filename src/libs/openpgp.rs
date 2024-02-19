use std::fs;

use super::{
    doip::{verify_proof, PrintFormat, Profile, VerifiedProof},
    error::AppError,
};
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::keys::openpgp::{fetch_hkp, fetch_wkd, get_keys_doip_proofs, read_key_from_string};
use futures::future::join_all;
use miette::Result;
use sequoia_openpgp::{packet::UserID, Cert};
use serde::Serialize;

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct KeyProfile {
    fingerprint: String,
    proof_uri: String,
    userid_proofs: Vec<UserIDVerifiedProofs>,
}

impl Profile for KeyProfile {
    fn print(&self, print_format: &PrintFormat) {
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

#[derive(Serialize)]
pub struct UserIDVerifiedProofs {
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

impl KeyProfile {
    pub async fn new_from_hkp(key_uri: String, key_server: Option<String>) -> Result<Vec<Self>> {
        let identifier = key_uri
            .split_once(':')
            .ok_or(AppError::ProfileURIMalformed)?
            .1;
        let certs = fetch_hkp(identifier, key_server.as_deref()).await?;
        let key_profiles_results: Vec<Result<Self>> =
            join_all(certs.into_iter().map(|x| async { Self::new(x).await })).await;
        let key_profiles: Vec<Self> = key_profiles_results
            .into_iter()
            .collect::<Result<Vec<Self>>>()?;

        Ok(key_profiles)
    }

    pub async fn new_from_wkd(key_uri: String) -> Result<Vec<Self>> {
        let certs = fetch_wkd(&key_uri[4..]).await?;
        let key_profiles_results: Vec<Result<Self>> =
            join_all(certs.into_iter().map(|x| async { Self::new(x).await })).await;
        let key_profiles: Vec<Self> = key_profiles_results
            .into_iter()
            .collect::<Result<Vec<Self>>>()?;

        Ok(key_profiles)
    }

    pub async fn new_from_file(key_path: String) -> Result<Self> {
        let file_contents: Result<String> = match fs::read_to_string(key_path) {
            Ok(s) => Ok(s),
            Err(error) => Err(AppError::FailedToReadKeyFile(error).into()),
        };
        let cert = read_key_from_string(&file_contents?)?;
        Self::new(cert).await
    }

    pub async fn new(cert: Cert) -> Result<Self> {
        #[allow(clippy::mutable_key_type)]
        let doip_proofs = get_keys_doip_proofs(&cert)?;

        let mut key_verified_proofs = KeyProfile {
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
}

fn user_id_to_user_id_string(user_id: UserID) -> String {
    let user_id_name = user_id.name2().unwrap_or(None).unwrap_or("");
    let user_id_email = user_id.email2().unwrap_or(None).unwrap_or("");
    format!("{user_id_name} <{user_id_email}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn openpgp_wkd() {
        let key_profiles = KeyProfile::new_from_wkd("wkd:alexis.lowe@chimbosonic.com".to_string())
            .await
            .unwrap();
        key_profiles[0].print(&PrintFormat::Text);
    }

    #[tokio::test]
    async fn openpgp_hkp_fingerprint() {
        let key_profiles = KeyProfile::new_from_hkp(
            "hkp:3637202523E7C1309AB79E99EF2DC5827B445F4B".to_string(),
            None,
        )
        .await
        .unwrap();
        key_profiles[0].print(&PrintFormat::Text);
    }

    #[tokio::test]
    async fn openpgp_hkp_email() {
        let key_profiles = KeyProfile::new_from_hkp("hkp:test@doip.rocks".to_string(), None)
            .await
            .unwrap();
        key_profiles[0].print(&PrintFormat::Text);
    }

    #[tokio::test]
    async fn openpgp_hkps() {
        let key_profiles = KeyProfile::new_from_hkp(
            "hkps:3637202523E7C1309AB79E99EF2DC5827B445F4B".to_string(),
            None,
        )
        .await
        .unwrap();
        key_profiles[0].print(&PrintFormat::Text);
    }

    #[tokio::test]
    async fn openpgp_from_file() {
        let key_profiles = KeyProfile::new_from_file(
            "__tests__/data/IETF_SAMPLE_PUBLIC_KEY_WITH_NOTATIONS.asc".to_string(),
        )
        .await
        .unwrap();
        key_profiles.print(&PrintFormat::Text);
    }
}
