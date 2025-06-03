use crate::rsa::PrivateKey;

use super::crypto::aes;
use super::crypto::rsa;
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Generate a random string containing letters and digits.
/// args:
/// :lenght: the number of char of the string
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

/// Use by thread to communicate with one client
/// args:
///     :stream: the stream to communicate with the client
fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    // ===================================
    // Hand shake
    // ===================================

    // generate a rsa session key + 8 char long string for aes
    let rsa_session_key = rsa::PrivateKey::generate();
    let serv_aes_key = generate_random_string(8);
    println!("private key : {:?}", rsa_session_key);
    println!("aes key : {:?}", serv_aes_key);

    // send the rsa public key
    stream.write_all(&rsa_session_key.pub_key.as_bytes())?;

    // receive the public key of the client
    let mut buffer = [0; 8];
    stream.read(&mut buffer).unwrap();
    let n = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let e = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let client_pub_key = rsa::PublicKey::new(n, e);

    // send the crypted aes key to the client
    let message = rsa::cypher_message(Vec::from(serv_aes_key.clone()), client_pub_key);
    stream.write_all(&message)?;

    // receive the client aes key
    let mut buffer = [0; 16];
    stream.read(&mut buffer).unwrap();
    let buffer = rsa::decypher_message(buffer.to_vec(), rsa_session_key);
    let client_aes_key = String::from_utf8(buffer).unwrap();

    // assemble the two part of the aes key
    let mut aes_session_key = serv_aes_key;
    aes_session_key.push_str(&client_aes_key);
    println!("client public key : {:?}", client_pub_key);
    println!("client aes key : {:?}", client_aes_key);
    println!("aes session key : {:?}", aes_session_key);

    Ok(())

    // généré la clé aes
    // let aes_key: [u8; 16] = generate_random_string(16).as_bytes().try_into().unwrap();
    // println!("aes key : {:?}", aes_key);

    // let cyphered_message = rsa::cypher_message(Vec::from(aes_key), pub_key);
    // stream.write_all(&cyphered_message).unwrap();

    // // étape 3: communiquer avec aes
    // loop {
    //     let mut buffer = [0; 1024];
    //     let bytes_read = stream.read(&mut buffer).unwrap();
    //     let decypher_request = aes::decypher_message(Vec::from(&buffer[..bytes_read]), aes_key);
    //     let request = String::from_utf8(decypher_request).unwrap();

    //     println!("Received request: {}", request);

    //     if request.trim() == "exit" {
    //         break;
    //     }

    //     let response = "HTTP/1.1 200 OK\n\nHello, world!";
    //     stream
    //         .write(&aes::cypher_message(Vec::from(response), aes_key))
    //         .unwrap();
    //     stream.flush().unwrap();
    // }
}

pub fn launch() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    println!("Server is running on {}", listener.local_addr().unwrap());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Failed to establish a connection: {}", e);
            }
        }
    }
}
