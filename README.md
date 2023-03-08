# doip-rs-cli (WIP)

CAUTION THIS IS A WORK IN PROGRESS AND COULD END UP MOVING

CLI interface to Keyoxide's doip-rs Library.

## Usage
```bash
cargo run -- --help
CLI interface to Keyoxide's doip-rs Library.

Usage: doip-rs-cli [OPTIONS]

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