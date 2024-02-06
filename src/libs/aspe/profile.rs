use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::claim::{Claim, VerificationResult};
use hex_color::HexColor;
use josekit::jwt::JwtPayload;
use serde::Serialize;

use crate::libs::{clap::PrintFormat, doip::VerifiedProof, error::ProofError};
use colored::customcolors::CustomColor;
use colored::Colorize;
#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct AspProfile {
    profile_uri: String,
    version: Option<u64>,
    name: Option<String>,
    description: Option<String>,
    color: Option<String>,
    verified_proofs: Option<Vec<VerifiedProof>>,
}

impl AspProfile {
    pub async fn from_jwt(profile_uri: &str, verified_payload: JwtPayload) -> Self {
        let version: Option<u64> = verified_payload
            .claim("http://ariadne.id/version")
            .and_then(|v| v.as_u64());
        let name: Option<String> = verified_payload
            .claim("http://ariadne.id/name")
            .and_then(|v| v.as_str().map(str::to_string));
        let description: Option<String> = verified_payload
            .claim("http://ariadne.id/description")
            .and_then(|v| v.as_str().map(str::to_string));
        let color: Option<String> = verified_payload
            .claim("http://ariadne.id/color")
            .and_then(|v| v.as_str().map(str::to_string));
        let claims_uris: Option<Vec<Option<String>>> = verified_payload
            .claim("http://ariadne.id/claims")
            .and_then(|v| {
                v.as_array()
                    .map(|v| v.iter().map(|v| v.as_str().map(str::to_string)).collect())
            });

        let verified_proofs = match claims_uris {
            Some(claim_uris) => {
                let mut verified_proofs = Vec::<VerifiedProof>::new();

                for claim_uri in claim_uris.into_iter().flatten() {
                    let claim = Claim::new(claim_uri.clone(), profile_uri.to_string());
                    let proof = match claim.find_matches() {
                        Ok(matches) => claim
                            .verify_with_matches(matches)
                            .await
                            .map_err(|error| {
                                ProofError::from(
                                    profile_uri.to_string(),
                                    claim_uri.to_string(),
                                    error,
                                )
                                .warn_proof_errors();
                                None::<VerificationResult>
                            })
                            .ok(),
                        Err(error) => {
                            ProofError::from(profile_uri.to_string(), claim_uri.to_string(), error)
                                .warn_proof_errors();
                            None
                        }
                    };
                    let verified_proof = VerifiedProof::new(claim_uri, proof);
                    verified_proofs.push(verified_proof)
                }
                Some(verified_proofs)
            }
            None => None,
        };

        Self {
            profile_uri: profile_uri.to_string(),
            version,
            name,
            description,
            color,
            verified_proofs,
        }
    }

    pub fn print(&self, print_format: &PrintFormat) {
        match print_format {
            PrintFormat::Json => println!("{self}"),
            PrintFormat::JsonPretty => println!("{self:?}"),
            PrintFormat::Text => {
                let hexcolor = HexColor::parse_rgb(&self.color.clone().unwrap()).unwrap();
                let custom = CustomColor {
                    r: hexcolor.r,
                    g: hexcolor.g,
                    b: hexcolor.b,
                };

                let mut print = String::new();
                print.push_str(
                    format!(
                        "Profile URI: {} Version: {}\n",
                        self.profile_uri,
                        self.version.unwrap_or(0)
                    )
                    .as_str(),
                );
                print.push_str(
                    format!("Name: {}\n", self.name.clone().unwrap_or("".to_string())).as_str(),
                );
                print.push_str(
                    format!(
                        "Description: {}\n",
                        self.description.clone().unwrap_or("".to_string())
                    )
                    .as_str(),
                );
                print.push_str(
                    format!(
                        "Claims: {}\n",
                        self.description.clone().unwrap_or("".to_string())
                    )
                    .as_str(),
                );

                if let Some(verified_proofs) = self.verified_proofs.as_ref() {
                    for verified_proof in verified_proofs {
                        if verified_proof.verification_result.is_some() {
                            print.push_str(format!("    {}: ✅\n", verified_proof.uri).as_str());
                        } else {
                            print.push_str(format!("    {}: ❌\n", verified_proof.uri).as_str());
                        }
                    }
                }

                print!("{}", print.custom_color(custom));
            }
        }
    }
}
