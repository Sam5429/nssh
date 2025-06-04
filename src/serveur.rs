use crate::rsa::PrivateKey;

use super::crypto::aes;
use super::crypto::rsa;
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
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

/// Send a string to a client by a stream using aes to cypher the string
fn send(stream: &mut TcpStream, message: String, aes_key: [u8; 16]) -> io::Result<()> {
    // Encrypt the message using AES
    let encrypted_message = aes::cypher_message(Vec::from(message), aes_key);

    // Send the encrypted message over the stream
    stream.write_all(&encrypted_message)?;
    Ok(())
}

/// Receive a cyphered string and decypher it before returning a string
fn receive(stream: &mut TcpStream, aes_key: [u8; 16]) -> io::Result<String> {
    // Read the encrypted message from the stream
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer)?;

    // Decrypt the message using AES
    let decrypted_message = aes::decypher_message(Vec::from(&buffer[..bytes_read]), aes_key);

    // Convert the decrypted message to a String
    String::from_utf8(decrypted_message).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Use by thread to communicate with one client
/// args:
///     :stream: the stream to communicate with the client
fn handle_client(mut stream: TcpStream) -> io::Result<std::net::SocketAddr> {
    let addr = stream.peer_addr().unwrap();
    println!("connection received: {}", addr);
    // ===================================
    // Hand shake
    // ===================================

    // generate a rsa session key + 8 char long string for aes
    let rsa_session_key = rsa::PrivateKey::generate();
    let server_aes_key = generate_random_string(8);

    // send the rsa public key
    stream.write_all(&rsa_session_key.pub_key.as_bytes())?;

    // receive the public key of the client
    let mut buffer = [0; 8];
    stream.read(&mut buffer).unwrap();
    let n = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let e = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let client_pub_key = rsa::PublicKey::new(n, e);

    // send the crypted aes key to the client
    let message = rsa::cypher_message(Vec::from(server_aes_key.clone()), client_pub_key);
    stream.write_all(&message)?;

    // receive the client aes key
    let mut buffer = [0; 16];
    stream.read(&mut buffer).unwrap();
    let buffer = rsa::decypher_message(buffer.to_vec(), rsa_session_key);
    let client_aes_key = String::from_utf8(buffer).unwrap();

    // assemble the two part of the aes key
    let aes_session_key = format!("{}{}", server_aes_key, client_aes_key);
    let aes_session_key: [u8; 16] = aes_session_key
        .as_bytes()
        .try_into()
        .expect("AES session key must be 16 bytes");
    println!("tunel up");

    // ==============================================
    // Authentification
    // =============================================

    // send it fingerprint
    let fingerprint = generate_random_string(16);
    send(&mut stream, fingerprint, aes_session_key)?;

    // receive ko if the connection is refused
    // receive login and password if the connection is accepted
    let response = receive(&mut stream, aes_session_key)?;
    if response == "KO" {
        stream.shutdown(Shutdown::Both)?;
        return Ok(addr);
    } else {
        let user_data = response.split("\n").collect::<Vec<&str>>();
        if user_data[0] != "admin" || user_data[1] != "admin" {
            send(
                &mut stream,
                String::from_str("login or password unknown").unwrap(),
                aes_session_key,
            )?;
            stream.shutdown(Shutdown::Both)?;
            return Ok(addr);
        }
    }

    send(
        &mut stream,
        String::from_str("connected").unwrap(),
        aes_session_key,
    )?;

    println!("Client authenticated successfully");

    // ========================================
    // Main communication loop
    // ========================================

    loop {
        // Receive a command from the client
        let command = match receive(&mut stream, aes_session_key) {
            Ok(cmd) => cmd.trim().to_string(),
            Err(_) => {
                break;
            }
        };

        if command == "exit" {
            break;
        }

        // Execute the command
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output();

        let response = match output {
            Ok(output) => {
                let mut resp = String::new();
                if !output.stdout.is_empty() {
                    resp.push_str(&String::from_utf8_lossy(&output.stdout));
                }
                if !output.stderr.is_empty() {
                    resp.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                if resp.is_empty() {
                    resp = String::from("Command executed, but no output.");
                }
                resp
            }
            Err(e) => format!("Failed to execute command: {}", e),
        };

        // Send the response back to the client
        if let Err(_) = send(&mut stream, response, aes_session_key) {
            break;
        }
    }

    Ok(addr)
}

pub fn launch() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    println!("Server is running on {}", listener.local_addr().unwrap());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| match handle_client(stream) {
                    Ok(addr) => println!("Client {} disconnected", addr),
                    Err(e) => eprintln!("Error handling client: {}", e),
                });
            }
            Err(e) => {
                eprintln!("Failed to establish a connection: {}", e);
            }
        }
    }
}
