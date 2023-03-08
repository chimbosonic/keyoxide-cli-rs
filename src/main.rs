use clap::Parser;
use display_json::{DebugAsJsonPretty, DisplayAsJson};
use doip::keys::openpgp::{fetch_hkp, get_keys_doip_proofs};
use miette::{Diagnostic, Result};
use sequoia_openpgp::{packet::UserID, Fingerprint};
use serde::Serialize;

use std::collections::HashMap;
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

async fn get_key_from_file_and_verify(_key_path: String, _pretty_print: bool) -> Result<()> {
    Err(AppError::Unimplemented {
        message: "Reading key from is not implemented",
    }
    .into())
}

async fn get_key_via_wkd_and_verify(_key_uri: String, _pretty_print: bool) -> Result<()> {
    Err(AppError::Unimplemented {
        message: "WKD is not implemented",
    }
    .into())
}

async fn get_key_via_hkp_and_verify(
    key_uri: String,
    key_server: Option<String>,
    pretty_print: bool,
) -> Result<()> {
    let hkp_results = fetch_hkp(&key_uri[4..], key_server.as_deref()).await;
    match hkp_results {
        Ok(certs) =>
        {
            #[allow(clippy::never_loop)]
            for cert in certs {
                match get_keys_doip_proofs(&cert) {
                    Ok(doip_proofs) => {
                        return verify_doip_proofs_and_print_results(
                            doip_proofs,
                            cert.fingerprint(),
                            pretty_print,
                        )
                        .await;
                    }
                    Err(error) => {
                        return Err(GenericDoipError {
                            doip_error_message: error,
                        }
                        .into())
                    }
                }
            }
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
    verified: bool,
}

#[allow(clippy::mutable_key_type)]
async fn verify_doip_proofs_and_print_results(
    doip_proofs: HashMap<UserID, Vec<String>>,
    key_fingerprint: Fingerprint,
    pretty_print: bool,
) -> Result<()> {
    let mut key_verified_proofs = KeyVerifiedProofs {
        fingerprint: key_fingerprint.to_hex(),
        user_id_proofs: Vec::new(),
    };

    for (user_id, proofs) in doip_proofs {
        let user_id_name = user_id.name().unwrap_or(None).unwrap_or("".to_string());
        let user_id_email = user_id.email().unwrap_or(None).unwrap_or("".to_string());
        let user_id_string = format!("{user_id_name} {user_id_email}");

        let mut verified_proofs = UserIDVerifiedProofs {
            userid: user_id_string,
            proofs: Vec::new(),
        };

        for proof in proofs {
            verified_proofs.proofs.push(VerifiedProof {
                uri: proof,
                verified: false,
            });
        }

        key_verified_proofs.user_id_proofs.push(verified_proofs);
    }
    if pretty_print {
        println!("{key_verified_proofs:?}");
    } else {
        println!("{key_verified_proofs}");
    }
    Ok(())
}
