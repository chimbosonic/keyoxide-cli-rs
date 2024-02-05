use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Uri for looking up a key can be (hkp:<email_address> || hkp:<key_fingerprint> || wkd:<email_address>)
    #[arg(short, long, required_unless_present_any(["input_key_file", "apse_uri"]))]
    pub fetch_key_uri: Option<String>,

    /// Domain name of keyserver used for hkp lookup. if not provided will default to keys.openpgp.org
    #[arg(short, long, required(false))]
    pub keyserver_domain: Option<String>,

    /// Path to file containing ASCII-Armored Public Key
    #[arg(short, long, required(false))]
    pub input_key_file: Option<String>,

    // APSE URI
    #[arg(short, long, required(false))]
    pub apse_uri: Option<String>,

    /// Pretty print output JSON
    #[arg(short, long)]
    pub pretty: bool,

    /// Pretty print output JSON
    #[arg(short, long)]
    pub skip_verify_ssl: bool,
}
