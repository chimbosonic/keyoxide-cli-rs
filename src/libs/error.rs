use doip::error::DoipError;

use miette::{Diagnostic, IntoDiagnostic, ReportHandler};
use std::{
    fmt,
    io::{self, prelude::*, stderr},
};
use thiserror::Error;

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

    #[allow(dead_code)]
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
