use crate::libs::doip::verify_proof;
use crate::libs::{doip::PrintFormat, doip::Profile, doip::VerifiedProof};
use colored::customcolors::CustomColor;
use colored::Colorize;
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use futures::future::join_all;
use hex_color::HexColor;
use miette::Result;
use serde::Serialize;

use self::jose::{fetch_jwt, parse_jws_and_generate_verified_asp_profile};
mod jose;

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]
pub struct AspProfile {
    profile_uri: String,
    version: Option<u64>,
    name: Option<String>,
    description: Option<String>,
    color: Option<String>,
    verified_proofs: Option<Vec<VerifiedProof>>,
}

impl Profile for AspProfile {
    fn print(&self, print_format: &PrintFormat) {
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

impl AspProfile {
    pub async fn new(profile_uri: &str, skip_verify_ssl: bool) -> Result<Self> {
        let jwt_unverified_string = fetch_jwt(profile_uri, skip_verify_ssl).await?;
        let verified_payload =
            parse_jws_and_generate_verified_asp_profile(&jwt_unverified_string).await?;

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
                let mut proofs_futures = Vec::new();

                for claim_uri in claim_uris.into_iter().flatten() {
                    let verification_result =
                        verify_proof(claim_uri.clone(), profile_uri.to_string());
                    proofs_futures.push(verification_result)
                }

                let proofs = join_all(proofs_futures)
                    .await
                    .into_iter()
                    .map(|(s, r)| VerifiedProof::new(s, r))
                    .collect();

                Some(proofs)
            }
            None => None,
        };

        Ok(Self {
            profile_uri: profile_uri.to_string(),
            version,
            name,
            description,
            color,
            verified_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aspe() {
        let asp_profile = AspProfile::new(&"aspe:keyoxide.org:TOICV3SYXNJP7E4P5AOK5DHW44", false)
            .await
            .unwrap();
        asp_profile.print(&PrintFormat::Text);
    }
}
