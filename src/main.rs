extern crate clap;

use clap::{Arg, App, ArgMatches};
use crypto::digest::Digest;
use crypto::sha2::Sha256;

mod client;
mod server;

fn main() {
    let matches = load_flags();
    let mut use_encryption = false;
    let key;

    let host = matches.value_of("host").unwrap_or("");

    // Decide if encryption is enabled
    if matches.is_present("key") {
        key = parse_key(matches.value_of("key"));
        use_encryption = true;
    } else if matches.is_present("password") {
        key = parse_password(matches.value_of("password"));
        use_encryption = true;
    } else {
        key = vec![0; 0];
    }

    // Start in listen mode or send mode
    if matches.is_present("listen") {
        server::start(host, use_encryption, key);
    } else {
        client::start(host, use_encryption, key);
    }
}

/// Takes the key from the argument list and returns a byte slice with the key
fn parse_key(key: Option<&str>) -> Vec<u8>  {
    if let Some(key_str) = key {
        if let Ok(key_bytes) = hex::decode(key_str) {
            if key_bytes.len() == 32 {
                return key_bytes;
            } else {
                eprintln!("The key has to be 32 bytes long.")
            }
        } else {
            eprintln!("Could not decode key.")
        }
    } else {
        eprintln!("Could not read the `key` argument.")
    }

    std::process::exit(1);
}

/// Takes the password from the argument list and converts it to a slice with the key
fn parse_password(password: Option<&str>) -> Vec<u8> {
    if let Some(password_str) = password {
        let mut hasher = Sha256::new();
        hasher.input_str(password_str);
        let mut out = vec![0; 32];
        hasher.result(&mut out);
        return out;
    } else {
        eprintln!("Could not read the `password` argument.")
    }

    std::process::exit(1);
}


/// Load all flags and parse the arguments
fn load_flags() -> ArgMatches<'static> {
    return App::new("Transpher")
    .version("1.0")
    .author("Mark N. <marknijboer8@gmail.com>")
    .about("Transhpers files")
    .arg(Arg::with_name("host")
        .short("h")
        .long("host")
        .required(true)
        .value_name("HOST:PORT")
        .help("Defines the host to connect to or to listen to"))
    .arg(Arg::with_name("listen")
        .short("l")
        .long("listen")
        .help("Enables listen mode"))
    .arg(Arg::with_name("key")
        .short("k")
        .long("key")
        .value_name("KEY")
        .help("The hexadecimal representation of the 32-byte encryption key. Setting the key or password enables AES-256 encryption for the transpher."))
    .arg(Arg::with_name("password")
        .short("p")
        .long("password")
        .value_name("PASSWORD")
        .help("A password used as a base for a generated 32-byte encryption key. Setting the key or password enables AES-256 encryption for the transpher."))
    .get_matches();
}