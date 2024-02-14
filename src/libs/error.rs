use doip::error::DoipError;

use miette::{Diagnostic, IntoDiagnostic, ReportHandler};
use std::{
    env, fmt,
    io::{self, prelude::*, stderr},
};
use thiserror::Error;

#[derive(Error, Diagnostic, Debug)]
pub enum AppError {
    // #[error(transparent)]
    // #[diagnostic(code(my_lib::io_error))]
    // IoError(#[from] std::io::Error),
    #[error("DOIP_PROFILE_URI does not match 'hkp:', 'hkps:', 'wkd:' or 'aspe:' pattern")]
    #[diagnostic(
        code(E0001),
        help("Make sure `-d, --doip-profile-uri <DOIP_PROFILE_URI>` follows one of these patterns (hkp(s):<email_address> || hkp(s):<key_fingerprint> || wkd:<email_address> || aspe:<profile_uri>)"),
    )]
    ProfileURIMalformed,

    #[error("No key was provided")]
    #[diagnostic(
        code(E0404),
        help("Neither `-d, --doip-profile-uri <DOIP_PROFILE_URI>` or `-i, --input-key-file <INPUT_KEY_FILE>` was provided")
    )]
    ProfileNotProvided,

    #[allow(dead_code)]
    #[error("Sorry this code path is Unimplemented")]
    #[diagnostic(code(E0000))]
    Unimplemented {
        #[help]
        message: &'static str,
    },

    #[error("Failed to Read Key File")]
    #[diagnostic(code(E0002))]
    FailedToReadKeyFile(#[from] io::Error),

    #[error("Failed to parse AspeUri please check format")]
    #[diagnostic(code(E0003))]
    FailedToParseAspeUri,

    #[error("Failed to parse aspe JWT")]
    #[diagnostic(code(E0004))]
    AspeJWTInvalid,

    #[error("Failed to fetch aspe JWT")]
    #[diagnostic(code(E0004))]
    FailedToFetchAspeJWT(#[from] reqwest::Error),
}

#[derive(Error, Diagnostic, Debug)]
#[error("Failed to verify {truncated_service_uri:?} for {proof_uri:?} due to {doip_error:?}")]
#[diagnostic(code(W0003), severity(Warning))]
pub struct ProofError {
    proof_uri: String,
    truncated_service_uri: String,
    doip_error: DoipError,
}

impl ProofError {
    pub fn warn_proof_errors(&self) {
        match env::var_os("RUST_LOG") {
            Some(rust_log) => {
                if !rust_log.eq_ignore_ascii_case("off") {
                    writeln!(stderr(), "{}", DisplayDiagnostic(self))
                        .into_diagnostic()
                        .unwrap()
                }
            }
            _ => writeln!(stderr(), "{}", DisplayDiagnostic(self))
                .into_diagnostic()
                .unwrap(),
        }
    }

    pub fn from(proof_uri: String, service_uri: String, doip_error: DoipError) -> Self {
        let mut truncated_service_uri = service_uri;
        truncated_service_uri.truncate(30);

        ProofError {
            proof_uri,
            truncated_service_uri,
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
