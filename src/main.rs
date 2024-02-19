use clap::Parser;
use miette::Result;
use std::env;

mod libs;
use libs::aspe::AspProfile;
use libs::clap::Args;
use libs::doip::Profile;
use libs::error::AppError;
use libs::openpgp::KeyProfile;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.quiet {
        env::set_var("RUST_LOG", "off");
    }

    if let Some(doip_profile_uri) = args.doip_profile_uri {
        return match &doip_profile_uri[..5] {
            "hkps:" | "hkp:" => {
                let key_profiles =
                    KeyProfile::new_from_hkp(doip_profile_uri, args.keyserver_domain).await?;
                for key_profile in key_profiles {
                    key_profile.print(&args.print_format);
                }
                Ok(())
            }
            "wkd:" => {
                let key_profiles = KeyProfile::new_from_wkd(doip_profile_uri).await?;
                for key_profile in key_profiles {
                    key_profile.print(&args.print_format);
                }
                Ok(())
            }
            "aspe:" => {
                let asp_profile = AspProfile::new(&doip_profile_uri, args.skip_verify_ssl).await?;
                asp_profile.print(&args.print_format);
                Ok(())
            }
            _ => Err(AppError::ProfileURIMalformed.into()),
        };
    }

    match args.input_key_file {
        Some(key_path) => {
            let key_profile = KeyProfile::new_from_file(key_path).await?;
            key_profile.print(&args.print_format);
            Ok(())
        }
        None => Err(AppError::ProfileNotProvided.into()),
    }
}
