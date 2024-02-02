use clap::Parser;
use doip::keys::openpgp::{fetch_hkp, fetch_wkd, read_key_from_string};
use miette::Result;
use sequoia_openpgp::Cert;
use std::fs;

mod libs;
use libs::clap::Args;
use libs::doip::KeyVerifiedProofs;
use libs::error::AppError;

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

async fn verify_doip_proofs_and_print_results(certs: Vec<Cert>, pretty_print: bool) -> Result<()> {
    for cert in certs {
        let key_verified_proofs = KeyVerifiedProofs::new(cert).await?;
        key_verified_proofs.print(pretty_print);
    }

    Ok(())
}
