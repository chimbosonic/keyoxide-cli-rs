use clap::Parser;
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::{
    claim::{Claim, VerificationResult},
    keys::openpgp::{fetch_hkp, fetch_wkd, get_keys_doip_proofs, read_key_from_string},
};
use miette::{Diagnostic, Result};
use sequoia_openpgp::Cert;
use serde::Serialize;
use std::{fs, io};
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
#[error("doip-rs had an error")]
#[diagnostic(code(doip::generic))]
pub struct GenericDoipError {
    #[help]
    doip_error_message: &'static str,
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

    let file_results = read_key_from_string(&file_contents?);
    match file_results {
        Ok(cert) => {
            verify_doip_proofs_and_print_results(vec![cert], pretty_print).await?;
        }
        Err(error) => {
            return Err(GenericDoipError {
                doip_error_message: error,
            }
            .into())
        }
    }
    Ok(())
}

async fn get_key_via_wkd_and_verify(key_uri: String, pretty_print: bool) -> Result<()> {
    match fetch_wkd(&key_uri[4..]).await {
        Ok(certs) => {
            verify_doip_proofs_and_print_results(certs, pretty_print).await?;
        }
        Err(error) => {
            return Err(GenericDoipError {
                doip_error_message: error,
            }
            .into())
        }
    }
    Ok(())
}

async fn get_key_via_hkp_and_verify(
    key_uri: String,
    key_server: Option<String>,
    pretty_print: bool,
) -> Result<()> {
    match fetch_hkp(&key_uri[4..], key_server.as_deref()).await {
        Ok(certs) => {
            verify_doip_proofs_and_print_results(certs, pretty_print).await?;
        }
        Err(error) => {
            return Err(GenericDoipError {
                doip_error_message: error,
            }
            .into());
        }
    }

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
    verification_result: Option<VerificationResult>,
}

#[allow(clippy::mutable_key_type)]
async fn verify_doip_proofs_and_print_results(certs: Vec<Cert>, pretty_print: bool) -> Result<()> {
    for cert in certs {
        match get_keys_doip_proofs(&cert) {
            Ok(doip_proofs) => {
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
                        let mut claim =
                            Claim::new(proof.clone(), key_verified_proofs.fingerprint.clone());
                        claim.find_match();
                        claim.verify().await;
                        #[allow(clippy::map_clone, clippy::redundant_clone)]
                        verified_proofs.proofs.push(VerifiedProof {
                            uri: proof,
                            verification_result: claim.get_verification_result().map(|t| t.clone()),
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
            Err(error) => {
                return Err(GenericDoipError {
                    doip_error_message: error,
                }
                .into())
            }
        }
    }

    Ok(())
}
