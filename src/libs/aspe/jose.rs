use josekit::{
    jwk::Jwk,
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, alg::eddsa::EddsaJwsAlgorithm, JwsHeader, JwsVerifier},
    jwt::{self, JwtPayload},
};

use crate::libs::error::AppError;

use super::profile::AspProfile;

use aspe_rs::aspe_uri::AspeUri;
use aspe_rs::constants;
use miette::Result;
use std::str::FromStr;

pub async fn parse_jws_and_generate_verified_asp_profile(
    profile_uri: &str,
    request_jws_str: &str,
) -> Result<AspProfile, AppError> {
    let profile_jwk = match extract_jwk_from_jwt(request_jws_str) {
        Some(x) => x,
        None => return Err(AppError::AspeJWTInvalid),
    };

    match profile_jwk.curve() {
        Some("Ed25519") => {
            let verifier = EddsaJwsAlgorithm::Eddsa
                .verifier_from_jwk(&profile_jwk)
                .map_err(|_| AppError::AspeJWTInvalid)?;
            let (verified_payload, _verified_header) =
                verify_and_get_jwt_payload(&verifier, request_jws_str)?;
            Ok(AspProfile::from_jwt(profile_uri, verified_payload).await)
        }
        Some("P-256") => {
            let verifier = EcdsaJwsAlgorithm::Es256
                .verifier_from_jwk(&profile_jwk)
                .map_err(|_| AppError::AspeJWTInvalid)?;
            let (verified_payload, _verified_header) =
                verify_and_get_jwt_payload(&verifier, request_jws_str)?;
            Ok(AspProfile::from_jwt(profile_uri, verified_payload).await)
        }
        _ => Err(AppError::AspeJWTInvalid),
    }
}

fn verify_and_get_jwt_payload(
    verifier: &dyn JwsVerifier,
    jws_string: &str,
) -> Result<(JwtPayload, JwsHeader), AppError> {
    match jwt::decode_with_verifier(jws_string, verifier) {
        Ok(x) => Ok(x),
        Err(_) => Err(AppError::AspeJWTInvalid),
    }
}

fn extract_jwk_from_jwt(jwt_str: &str) -> Option<Jwk> {
    let jwt_header = match jwt::decode_header(jwt_str) {
        Ok(x) => x,
        Err(_) => return None,
    };
    let jwt_header_jwk = match jwt_header.claim("jwk") {
        Some(x) => x,
        None => return None,
    };
    let jwt_header_jwk = match jwt_header_jwk.as_object() {
        Some(x) => x,
        None => return None,
    };
    match Jwk::from_map(jwt_header_jwk.to_owned()) {
        Ok(x) => Some(x),
        Err(_) => None,
    }
}

pub async fn fetch_jwt(aspe_uri: &str, skip_verify_ssl: bool) -> Result<String, AppError> {
    let aspe_uri: AspeUri =
        AspeUri::from_str(aspe_uri).map_err(|_| AppError::FailedToParseAspeUri)?;

    let url = format!(
        "https://{}{}{}",
        &aspe_uri.domain_part,
        constants::GET_ID_URL_PATH,
        &aspe_uri.local_part
    );

    let res = reqwest::Client::builder()
        .danger_accept_invalid_certs(skip_verify_ssl)
        .build()
        .map_err(AppError::FailedToFetchAspeJWT)?
        .get(url)
        .header(reqwest::header::CONTENT_TYPE, constants::JWS_MIME)
        .send()
        .await
        .map_err(AppError::FailedToFetchAspeJWT)?;

    res.text().await.map_err(AppError::FailedToFetchAspeJWT)
}
