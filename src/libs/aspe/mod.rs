use josekit::{    
    jwk::Jwk,
    jws::{JwsHeader, JwsVerifier, alg::eddsa::EddsaJwsAlgorithm, alg::ecdsa::EcdsaJwsAlgorithm},
    jwt::{self, JwtPayload, JwtPayloadValidator},
};

mod profile;
use profile::AspProfile;

pub fn parse_and_verify_request_jws(request_jws_str: &str) -> Result<(), &'static str> {
    let profile_jwk = match extract_jwk_from_jwt(request_jws_str) {
        Some(x) => x,
        None => return Err("Invalid JWK"),
    };

    match profile_jwk.curve().unwrap() {
        "Ed25519" => {
            let verifier = EddsaJwsAlgorithm::Eddsa.verifier_from_jwk(&profile_jwk).unwrap();
            let (verified_payload,verified_header) = verify_and_get_jwt_payload(&verifier,request_jws_str)?;
            print!("{verified_payload:?}");
            let asp_profile = AspProfile::from_jwt(verified_payload,verified_header);
            println!("{asp_profile:?}");
        },
        "P-256" => {
            let verifier = EcdsaJwsAlgorithm::Es256.verifier_from_jwk(&profile_jwk).unwrap();
            let (verified_payload,verified_header) = verify_and_get_jwt_payload(&verifier,request_jws_str)?;
            print!("{verified_payload:?}");
            let asp_profile = AspProfile::from_jwt(verified_payload,verified_header);
            println!("{asp_profile:?}");
        },
        _ => return Err("Invalid JWK"),
    };

    Ok(())


}

fn verify_and_get_jwt_payload(verifier: &dyn JwsVerifier, jws_string: &str) -> Result<(JwtPayload,JwsHeader), &'static str>{
    match jwt::decode_with_verifier(jws_string, verifier) {
        Ok(x) => {
            Ok(x)
        },
        Err(_) => return Err("Invalid JWK"),
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
