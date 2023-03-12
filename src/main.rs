use clap::Parser;
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::{
    claim::{Claim, VerificationResult},
    error::DoipError,
    keys::openpgp::{fetch_hkp, fetch_wkd, get_keys_doip_proofs, read_key_from_string},
    service_provider::SPAbout,
};
use miette::{Diagnostic, Result};
use miette::{IntoDiagnostic, ReportHandler};
use sequoia_openpgp::Cert;
use serde::Serialize;
use std::{
    fmt, fs,
    io::{self, prelude::*, stderr},
};
use thiserror::Error;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Uri for looking up a key can be (hkp:<email_address> || hkp:<key_fingerprint> || wkd:<email_address>)
    #[arg(short, long, required_unless_present("input_key_file"))]
    fetch_key_uri: Option<String>,

    /// Domain name of keyserver used for hkp lookup. if not provided will default to keys.openpgp.org
    #[arg(short, long, required(false))]
    keyserver_domain: Option<String>,

    /// Path to file containing ASCII-Armored Public Key
    #[arg(short, long, required(false))]
    input_key_file: Option<String>,

    /// Pretty print output JSON
    #[arg(short, long)]
    pretty: bool,
}

#[derive(Error, Diagnostic, Debug)]
pub enum AppError {
    // #[error(transparent)]
    // #[diagnostic(code(my_lib::io_error))]
    // IoError(#[from] std::io::Error),
    #[error("FETCH_KEY_URI does not match 'hkp:', 'hkps:' or 'wkd'")]
    #[diagnostic(
        code(E0001),
        help("Make sure `-f, --fetch-key-uri <FETCH_KEY_URI>` follows one of these patterns (hkp:<email_address> || hkp:<key_fingerprint> || wkd:<email_address>)"),
    )]
    KeyURIMalformed,

    #[error("No key was provided")]
    #[diagnostic(
        code(E0404),
        help("Neither `-f, --fetch-key-uri <FETCH_KEY_URI>` or `-i, --input-key-file <INPUT_KEY_FILE>` was provided")
    )]
    KeyNotProvided,

    #[error("Sorry this code path is Unimplemented")]
    #[diagnostic(code(E0000))]
    Unimplemented {
        #[help]
        message: &'static str,
    },

    #[error("Sorry this code path is Unimplemented")]
    #[diagnostic(code(E0002))]
    FailedToReadKeyFile(#[from] io::Error),
}

#[derive(Error, Diagnostic, Debug)]
#[error("Failed to verify {truncated_proof:?} for {userid:?} due to {doip_error:?}")]
#[diagnostic(code(W0003), severity(Warning))]
pub struct ProofError {
    userid: String,
    truncated_proof: String,
    doip_error: DoipError,
}

impl ProofError {
    pub fn warn_proof_errors(&self) {
        writeln!(stderr(), "{}", DisplayDiagnostic(self))
            .into_diagnostic()
            .unwrap();
    }

    pub fn from(proof: String, userid: String, doip_error: DoipError) -> Self {
        let mut truncated_proof = proof;
        truncated_proof.truncate(30);

        ProofError {
            userid,
            truncated_proof,
            doip_error,
        }
    }
}

struct DisplayDiagnostic<'a>(&'a dyn miette::Diagnostic);
impl fmt::Display for DisplayDiagnostic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        miette::GraphicalReportHandler::new().debug(self.0, f)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.fetch_key_uri {
        Some(key_uri) => match &key_uri[..4] {
            "hkps:" | "hkp:" => {
                return get_key_via_hkp_and_verify(key_uri, args.keyserver_domain, args.pretty)
                    .await;
            }
            "wkd:" => {
                return get_key_via_wkd_and_verify(key_uri, args.pretty).await;
            }
            _ => Err(AppError::KeyURIMalformed.into()),
        },
        None => match args.input_key_file {
            Some(key_path) => get_key_from_file_and_verify(key_path, args.pretty).await,
            None => Err(AppError::KeyNotProvided.into()),
        },
    }
}

async fn get_key_from_file_and_verify(key_path: String, pretty_print: bool) -> Result<()> {
    let file_contents: Result<String> = match fs::read_to_string(key_path) {
        Ok(s) => Ok(s),
        Err(error) => Err(AppError::FailedToReadKeyFile(error).into()),
    };

    let cert = read_key_from_string(&file_contents?)?;
    verify_doip_proofs_and_print_results(vec![cert], pretty_print).await?;
    Ok(())
}

async fn get_key_via_wkd_and_verify(key_uri: String, pretty_print: bool) -> Result<()> {
    let certs = fetch_wkd(&key_uri[4..]).await?;
    verify_doip_proofs_and_print_results(certs, pretty_print).await?;
    Ok(())
}

async fn get_key_via_hkp_and_verify(
    key_uri: String,
    key_server: Option<String>,
    pretty_print: bool,
) -> Result<()> {
    let certs = fetch_hkp(&key_uri[4..], key_server.as_deref()).await?;
    verify_doip_proofs_and_print_results(certs, pretty_print).await?;
    Ok(())
}

#[derive(Serialize, DisplayAsJson, DebugAsJsonPretty)]

struct KeyVerifiedProofs {
    fingerprint: String,
    user_id_proofs: Vec<UserIDVerifiedProofs>,
}

#[derive(Serialize)]

struct UserIDVerifiedProofs {
    userid: String,
    proofs: Vec<VerifiedProof>,
}

#[derive(Serialize)]
struct VerifiedProof {
    uri: String,
    verification_result: Option<AppVerificationResult>,
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

#[allow(clippy::mutable_key_type)]
async fn verify_doip_proofs_and_print_results(certs: Vec<Cert>, pretty_print: bool) -> Result<()> {
    for cert in certs {
        let doip_proofs = get_keys_doip_proofs(&cert)?;
        let mut key_verified_proofs = KeyVerifiedProofs {
            fingerprint: cert.fingerprint().to_hex(),
            user_id_proofs: Vec::new(),
        };

        for (user_id, proofs) in doip_proofs {
            let user_id_name = user_id.name().unwrap_or(None).unwrap_or("".to_string());
            let user_id_email = user_id.email().unwrap_or(None).unwrap_or("".to_string());
            let user_id_string = format!("{user_id_name} <{user_id_email}>");

            let mut verified_proofs = UserIDVerifiedProofs {
                userid: user_id_string,
                proofs: Vec::new(),
            };

            for proof in proofs {
                let claim = Claim::new(proof.clone(), key_verified_proofs.fingerprint.clone());
                let verification_result: Option<VerificationResult> = match claim.find_matches() {
                    Ok(matches) => claim
                        .verify_with_matches(matches)
                        .await
                        .map_err(|error| {
                            ProofError::from(proof.clone(), verified_proofs.userid.clone(), error)
                                .warn_proof_errors();
                            None::<VerificationResult>
                        })
                        .ok(),
                    Err(error) => {
                        ProofError::from(proof.clone(), verified_proofs.userid.clone(), error)
                            .warn_proof_errors();
                        None
                    }
                };

                #[allow(clippy::map_clone, clippy::redundant_clone)]
                verified_proofs.proofs.push(VerifiedProof {
                    uri: proof.clone(),
                    verification_result: verification_result.map(AppVerificationResult::from),
                });
            }
            key_verified_proofs.user_id_proofs.push(verified_proofs);
            key_verified_proofs
                .user_id_proofs
                .sort_by(|a, b| b.userid.cmp(&a.userid));
        }
        if pretty_print {
            println!("{key_verified_proofs:?}");
        } else {
            println!("{key_verified_proofs}");
        }
    }

    Ok(())
}
