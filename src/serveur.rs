use super::crypto::rsa;
use rand::Rng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::{result, thread};

// Fonction pour générer une chaîne de caractères aléatoires
fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn handle_client(mut stream: TcpStream, private_key: Arc<rsa::PrivateKey>) {
    // récéption et mise en forme de la clé public
    let mut buffer = [0; 8];
    stream.read(&mut buffer).unwrap();
    println!("{:?}", buffer);
    let n = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let e = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let pub_key = rsa::PublicKey::new(n, e);

    println!("Received public key: {:?}", pub_key);

    // généré la clé aes
    let aes_key = generate_random_string(16);
    println!("{}", aes_key);
    println!("public key : {:?}", private_key);

    // concatène les infos
    let mut message = private_key.pub_key.as_bytes();
    message.extend_from_slice(&mut aes_key.as_bytes());

    // envoie les infos

    let cyphered_message = rsa::cypher_message(message, pub_key);
    stream.write_all(&cyphered_message).unwrap();

    // étape 1: recevoir la clé public du client

    // étape 2: utiliser la clé du client pour envoyé ta clé public ainsi que la clé aes

    // étape 3: communiquer avec aes
    loop {
        let mut buffer = [0; 512];
        stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..]);

        println!("Received request: {}", request);

        if request.trim() == "exit" {
            break;
        }

        let response = "HTTP/1.1 200 OK\n\nHello, world!";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

pub fn launch() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let private_key = Arc::new(rsa::PrivateKey::generate());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let private_key_clone = private_key.clone();
                thread::spawn(|| {
                    handle_client(stream, private_key_clone);
                });
            }
            Err(e) => {
                eprintln!("Failed to establish a connection: {}", e);
            }
        }
    }
}
