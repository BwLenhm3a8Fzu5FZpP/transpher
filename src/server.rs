use std::net::{TcpListener, TcpStream};
use std::io::{self, Write, Read};
use aes_gcm::{Aes256Gcm};
use aead::{Aead, NewAead, generic_array::GenericArray};

pub fn start(host: &str, use_encryption: bool, key: Vec<u8>) {
    if let Ok(listener) = TcpListener::bind(host) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if use_encryption {
                        handle_decrypted_stream(stream, key);
                    } else {
                        handle_stream(stream);
                    }
                },
                Err(e) => { 
                    eprintln!("Could open connection to client. Error: {}", e);
                    return;
                }
            }
            break;
        }
    } else {
        eprintln!("Could not listen on the given host");
        return;
    }
}

fn handle_stream(mut stream: TcpStream) {
    let buffer = &mut [0; 2048];
    let mut stdout = io::stdout();
    loop {
        match stream.read(&mut buffer[..]) {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                if let Err(e) = stdout.write(&buffer[..size]) {
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

fn handle_decrypted_stream(mut stream: TcpStream, key: Vec<u8>) {
    let buffer = &mut [0; 2076];
    let mut stdout = io::stdout();
    let aead = Aes256Gcm::new(&GenericArray::from_slice(key.as_slice()));
    loop {
        match stream.read(&mut buffer[..]) {
            Ok(size) => {
                if size == 0 {
                    break;
                }

                let decrypted = decrypt(&buffer[..size], &aead);
                if let Err(e) = stdout.write(&decrypted) {
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

fn decrypt(buffer: &[u8], aead: &Aes256Gcm) -> Vec<u8> {
    let nonce = GenericArray::from_slice(&buffer[..12]);
    let plaintext = aead.decrypt(nonce, &buffer[12..]);

    match plaintext {
        Ok(plain) => {
            return plain;
        },
        Err(e) => {
            eprintln!("Could not decrypt: {:?}", e);
            return vec![0; 0];
        }
    }
}