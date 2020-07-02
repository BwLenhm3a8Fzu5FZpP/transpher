use std::net::TcpStream;
use std::io::{self, Read, Write};
use aes_gcm::Aes256Gcm;
use rand::Rng;
use aead::{Aead, NewAead, generic_array::GenericArray};
use safemem::prepend;

pub fn start(host: &str, use_encryption: bool, key: Vec<u8>) {
    if let Ok(connection) = TcpStream::connect(host) {
        if use_encryption {
            handle_encrypted_stream(connection, key);
        } else {
            handle_stream(connection);
        }
    } else {
        eprintln!("Could not connect to the given host");
        return;
    }
}

fn handle_stream(mut stream: TcpStream) {
    let mut stdin = io::stdin();
    let mut buffer = [0; 2048];

    loop {
        match stdin.read(&mut buffer[..]) {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                if let Err(e) = stream.write(&buffer[..size]) {
                    eprintln!("{}", e);
                    return;
                }
            },
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        }
    }
}

fn handle_encrypted_stream(mut stream: TcpStream, key: Vec<u8>) {
    let mut stdin = io::stdin();
    let mut buffer = [0; 2048];
    let aead = Aes256Gcm::new(&GenericArray::from_slice(key.as_slice()));

    loop {
        match stdin.read(&mut buffer[..]) {
            Ok(size) => {
                if size == 0 {
                    break;
                }

                let encrypted = encrypt(&buffer[..size], &aead);
                if let Err(e) = stream.write(&encrypted) {
                    eprintln!("{}", e);
                    return;
                }
            },
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        }
    }
}

fn encrypt(buffer: &[u8], aead: &Aes256Gcm) -> Vec<u8> {
    let nonce_slice = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = GenericArray::from_slice(&nonce_slice);
    let ciphertext = aead.encrypt(nonce, buffer);

    match ciphertext {
        Ok(mut cipher) => {
            prepend(&nonce_slice, &mut cipher);
            return cipher;
        },
        Err(e) => {
            eprintln!("{:?}", e);
            return vec![0; 0];
        }
    }
}