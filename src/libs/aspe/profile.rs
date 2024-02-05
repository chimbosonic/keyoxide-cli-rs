use aspe_rs::jwk::get_fingerprint;
use doip::claim::Claim;
use josekit::{jws::JwsHeader, jwt::JwtPayload};


#[derive(Debug)]
pub struct AspProfile {
    version: Option<u64>,
    name: Option<String>,
    description: Option<String>,
    color: Option<String>,
    claims: Option<Vec<Claim>>,
}

impl AspProfile {
    pub fn from_jwt(verified_payload: JwtPayload, verified_header: JwsHeader) -> Self{
        let version: Option<u64> = verified_payload.claim("http://ariadne.id/version").map_or(None, |v| {v.as_u64()});
        let name: Option<String> = verified_payload.claim("http://ariadne.id/name").map_or(None, |v| {v.as_str().map(str::to_string)});
        let description: Option<String> = verified_payload.claim("http://ariadne.id/description").map_or(None, |v| {v.as_str().map(str::to_string)});
        let color: Option<String> = verified_payload.claim("http://ariadne.id/color").map_or(None, |v| {v.as_str().map(str::to_string)});
        let fingerprint = get_fingerprint(&verified_header.jwk().unwrap()).unwrap();
        println!("{fingerprint:?}");
        
        Self {
            version,
            name,
            description,
            color,
            claims: None
        }
    }


    // async fn verify_proof(proof: &str, fingerprint: &str) -> Option<VerificationResult> {
    //     let claim = Claim::new(proof.to_string(), fingerprint.to_string());
    //     match claim.find_matches() {
    //         Ok(matches) => claim
    //             .verify_with_matches(matches)
    //             .await
    //             .map_err(|error| {
    //                 ProofError::from(proof.to_string(), userid.to_string(), error).warn_proof_errors();
    //                 None::<VerificationResult>
    //             })
    //             .ok(),
    //         Err(error) => {
    //             ProofError::from(proof.to_string(), userid.to_string(), error).warn_proof_errors();
    //             None
    //         }
    //     }
    // }
}