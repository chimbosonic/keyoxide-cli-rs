use clap::Parser;
use doip::keys::openpgp::{fetch_hkp, fetch_wkd, read_key_from_string};
use libs::aspe::jose::{fetch_jwt, parse_jws_and_generate_verified_asp_profile};
use miette::Result;
use sequoia_openpgp::Cert;
use std::{env, fs};

mod libs;
use libs::clap::{Args, PrintFormat};
use libs::error::AppError;
use libs::openpgp::KeyVerifiedProofs;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.quiet {
        env::set_var("RUST_LOG", "off");
    }

    if let Some(doip_profile_uri) = args.doip_profile_uri {
        return match &doip_profile_uri[..5] {
            "hkps:" | "hkp:" => {
                get_key_via_hkp_and_verify(doip_profile_uri, args.keyserver_domain, &args.print_format).await
            }
            "wkd:" => get_key_via_wkd_and_verify(doip_profile_uri, &args.print_format).await,
            "aspe:" => get_aspe_profile_and_verify(doip_profile_uri, args.skip_verify_ssl, &args.print_format).await,
            _ => Err(AppError::ProfileURIMalformed.into()),
        };
    }

    match args.input_key_file {
        Some(key_path) => get_key_from_file_and_verify(key_path, &args.print_format).await,
        None => Err(AppError::ProfileNotProvided.into()),
    }
}

async fn get_aspe_profile_and_verify(
    aspe_uri: String,
    skip_verify_ssl: bool,
    print_format: &PrintFormat,
) -> Result<()> {
    let asp_profile_jwt_string = fetch_jwt(&aspe_uri, skip_verify_ssl).await?;
    let asp_profile =
        parse_jws_and_generate_verified_asp_profile(&aspe_uri, &asp_profile_jwt_string)
            .await
            .map_err(|_e| AppError::FailedToParseAspeUri)?;
    asp_profile.print(print_format);
    Ok(())
}

async fn get_key_from_file_and_verify(key_path: String, print_format: &PrintFormat) -> Result<()> {
    let file_contents: Result<String> = match fs::read_to_string(key_path) {
        Ok(s) => Ok(s),
        Err(error) => Err(AppError::FailedToReadKeyFile(error).into()),
    };
    let cert = read_key_from_string(&file_contents?)?;
    verify_doip_proofs_and_print_results(vec![cert], print_format).await?;
    Ok(())
}

async fn get_key_via_wkd_and_verify(key_uri: String, print_format: &PrintFormat) -> Result<()> {
    let certs = fetch_wkd(&key_uri[4..]).await?;
    verify_doip_proofs_and_print_results(certs, print_format).await?;
    Ok(())
}

async fn get_key_via_hkp_and_verify(
    key_uri: String,
    key_server: Option<String>,
    print_format: &PrintFormat,
) -> Result<()> {
    let identifier = key_uri.split_once(":").ok_or(AppError::ProfileURIMalformed)?.1;
    let certs = fetch_hkp(identifier, key_server.as_deref()).await?;
    verify_doip_proofs_and_print_results(certs, print_format).await?;
    Ok(())
}

async fn verify_doip_proofs_and_print_results(
    certs: Vec<Cert>,
    print_format: &PrintFormat,
) -> Result<()> {
    for cert in certs {
        let key_verified_proofs = KeyVerifiedProofs::new(cert).await?;
        key_verified_proofs.print(print_format);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aspe() {
        get_aspe_profile_and_verify(
            "aspe:keyoxide.org:TOICV3SYXNJP7E4P5AOK5DHW44".to_string(),
            false,
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn openpgp_wkd() {
        get_key_via_wkd_and_verify(
            "wkd:alexis.lowe@chimbosonic.com".to_string(),
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn openpgp_hkp_fingerprint() {
        get_key_via_hkp_and_verify(
            "hkp:3637202523E7C1309AB79E99EF2DC5827B445F4B".to_string(),
            None,
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn openpgp_hkp_email() {
        get_key_via_hkp_and_verify(
            "hkp:test@doip.rocks".to_string(),
            None,
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn openpgp_hkps() {
        get_key_via_hkp_and_verify(
            "hkp:3637202523E7C1309AB79E99EF2DC5827B445F4B".to_string(),
            None,
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }


    #[tokio::test]
    async fn openpgp_from_file() {
        get_key_from_file_and_verify(
            "__tests__/data/IETF_SAMPLE_PUBLIC_KEY_WITH_NOTATIONS.asc".to_string(),
            &PrintFormat::Text,
        )
        .await
        .unwrap();
    }

}
