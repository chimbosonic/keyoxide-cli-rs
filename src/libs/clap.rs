#[derive(clap::Parser, Debug)]
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

    ///Print Format
    #[clap(value_enum, default_value_t)]
    #[arg(short, long)]
    pub print_format: PrintFormat,

    /// Skip SSL Verification for Aspe Profile Fetch
    #[arg(short, long)]
    pub skip_verify_ssl: bool,

    /// Set Logging to Quiet
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum PrintFormat {
    Json,
    JsonPretty,
    #[default]
    Text,
}
