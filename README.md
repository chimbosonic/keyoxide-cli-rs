# keyoxide-cli-rs (WIP)

CAUTION THIS IS A WORK IN PROGRESS AND COULD END UP MOVING

CLI interface to doip-rs library written in rust.

Currently this uses:
`doip = { git = "https://codeberg.org/keyoxide/doip-rs.git", branch = "dev", version = "0.1.0" }`
`doip-openpgp = { git = "https://codeberg.org/keyoxide/doip-rs.git", branch = "dev", version = "0.1.0" }`
`aspe-rs = { git = "https://codeberg.org/keyoxide/aspe-rs.git", branch = "main", version = "0.1.0" }`

## Releases and Pipeline

There is a mirror at [https://github.com/chimbosonic/keyoxide-cli-rs](https://github.com/chimbosonic/keyoxide-cli-rs) which has Builds and Releases with the build artifacts.

You can use those if you don't want to pull and build this yourself.

Currently it builds a MacOS binary and a Linux binary.

## Install

Clone the repo and run the following from the repo's root:

```bash
cargo install --path .
```

## Usage

![demo](./demo.gif)

```bash
keyoxide --help
CLI interface to Keyoxide's doip-rs Library.

Usage: keyoxide [OPTIONS]

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

## Supported targets

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
