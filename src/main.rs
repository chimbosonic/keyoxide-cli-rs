use aspe_rs::asp_profile::AspProfile;
use aspe_rs::aspe_uri::AspeUri;
use aspe_rs::constants;
use clap::Parser;
use doip::keys::openpgp::{fetch_hkp, fetch_wkd, read_key_from_string};
use josekit::jwk::Jwk;
use miette::Result;
use sequoia_openpgp::Cert;
use serde_json::{Map, Value};
use std::fs;
use std::io::{Read};
use bytes::Bytes;
use std::str::FromStr;
use josekit::jwt;

mod libs;
use libs::clap::Args;
use libs::doip::KeyVerifiedProofs;
use libs::error::AppError;

use crate::libs::aspe::parse_and_verify_request_jws;


#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(key_uri) = args.fetch_key_uri {
        return match &key_uri[..4] {
            "hkps:" | "hkp:" => {
                get_key_via_hkp_and_verify(key_uri, args.keyserver_domain, args.pretty)
                    .await
            },
            "wkd:" => {
                get_key_via_wkd_and_verify(key_uri, args.pretty).await
            },
            _ => Err(AppError::KeyURIMalformed.into()),
        };
    }

    if let Some(aspe_uri) = args.apse_uri {
        return get_aspe_profile_and_verify(aspe_uri).await;
    }

    match args.input_key_file {
        Some(key_path) => get_key_from_file_and_verify(key_path, args.pretty).await,
        None => Err(AppError::KeyNotProvided.into()),
    }
}

async fn get_aspe_profile_and_verify(aspe_uri: String) -> Result<()> {
    let aspe_uri: AspeUri = AspeUri::from_str(&aspe_uri).map_err(|_| AppError::FailedToParseAspeUri)?;
    let client = reqwest::Client::new();

    let url = format!("https://{}{}{}", &aspe_uri.domain_part, constants::GET_ID_URL_PATH, &aspe_uri.local_part);
    let req = client
        .get(url)
        .header(reqwest::header::CONTENT_TYPE, constants::JWS_MIME)
        .build().unwrap();

    let res = client.execute(req).await;

    let res = res.unwrap();
    let data = res.text().await.unwrap();
    println!("{data:?}");
    parse_and_verify_request_jws(&data); 

    Ok(()) 
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
