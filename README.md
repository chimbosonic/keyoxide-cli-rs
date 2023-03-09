# keyoxide-cli-rs (WIP)

CAUTION THIS IS A WORK IN PROGRESS AND COULD END UP MOVING

CLI interface to doip-rs library written in rust.
Currently this uses `doip = { git = "https://codeberg.org/chimbosonic/doip-rs.git", branch = "fixClaimsForCLI", version = "0.1.0" }`

## Install
Clone the repo and run the following from the repo's root:
```bash
cargo install --path .
```

## Usage
Currently to run verification you need `src/config/serviceProviderDefinitions` in your path from where you execute the tool.
This is due to how serviceProviders are defined this will soon be fixed.

```bash
keyoxide --help
CLI interface to Keyoxide's doip-rs Library.

Usage: keyoxide-cli [OPTIONS]

Options:
  -f, --fetch-key-uri <FETCH_KEY_URI>
          Uri for looking up a key can be (hkp:<email_address> || hkp:<key_fingerprint> || wkd:<email_address>)
  -k, --keyserver-domain <KEYSERVER_DOMAIN>
          Domain name of keyserver used for hkp lookup. if not provided will default to keys.openpgp.org
  -i, --input-key-file <INPUT_KEY_FILE>
          Path to file containing ASCII-Armored Public Key
  -p, --pretty
          Pretty print output JSON
  -h, --help
          Print help
  -V, --version
          Print version
```