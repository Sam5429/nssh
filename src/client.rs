use crate::crypto::aes;
use crate::crypto::rsa;
use crate::crypto::sha;
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::str::FromStr;

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
    let mut buff = [0; 2];

    // Send the message
    let encrypted_message = aes::cypher_message(Vec::from(message.clone()), aes_key);
    stream.write_all(&encrypted_message)?;
    stream.read(&mut buff)?; // Tempo so that the server can read the message and not block

    // Send the hash of the concatenation of the message and the aes_key
    let mut message_and_key = Vec::from(message.as_bytes());
    message_and_key.extend_from_slice(&aes_key);

    let hash_u32 = sha::sha256(message_and_key);
    let mut hash = Vec::with_capacity(hash_u32.len() * 4);
    hash_u32.iter().for_each(|h| {
        hash.extend_from_slice(&h.to_be_bytes());
    });
    stream.write_all(&hash)?;

    Ok(())
}

/// Receive a cyphered string and decypher it before returning a string
fn receive(stream: &mut TcpStream, aes_key: [u8; 16]) -> io::Result<String> {
    // Read the encrypted message from the stream
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer)?;
    stream.write_all("OK".as_bytes())?;

    // Decrypt the message using AES
    let decrypted_message = aes::decypher_message(Vec::from(&buffer[..bytes_read]), aes_key);
    let message = String::from_utf8(decrypted_message.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));

    // Read the hash from the stream
    let mut hash_buffer = [0; 32]; // SHA-256 produces a 32-byte hash
    stream.read(&mut hash_buffer)?;

    // Create the expected hash from the decrypted message
    let mut message_and_key = Vec::from(message.as_ref().unwrap().as_bytes());
    message_and_key.extend_from_slice(&aes_key);
    let expected_hash = sha::sha256(message_and_key);

    // Compare the two hashes to see if they are identical
    let mut expected_hash_bytes: Vec<u8> = Vec::with_capacity(expected_hash.len() * 4);
    expected_hash.iter().for_each(|h| {
        expected_hash_bytes.extend_from_slice(&h.to_be_bytes());
    });

    if expected_hash_bytes != hash_buffer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hash verification failed",
        ));
    }

    message
}

pub fn connect_and_communicate() -> io::Result<()> {
    // =============================================
    // Connection to the server
    // =============================================
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;

    // ==========================================
    // Hand shake
    // =========================================

    // generate a rsa session key + 8 char long string for aes
    let rsa_session_key = rsa::PrivateKey::generate();
    let client_aes_key = generate_random_string(8);

    // send the rsa public key
    stream.write_all(&rsa_session_key.pub_key.as_bytes())?;

    // receive the public key of the client
    let mut buffer = [0; 8];
    stream.read(&mut buffer).unwrap();
    let n = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let e = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let server_pub_key = rsa::PublicKey::new(n, e);

    // send the crypted aes key to the client
    let message = rsa::cypher_message(Vec::from(client_aes_key.clone()), server_pub_key);
    stream.write_all(&message)?;

    // receive the client aes key
    let mut buffer = [0; 16];
    stream.read(&mut buffer).unwrap();
    let buffer = rsa::decypher_message(buffer.to_vec(), rsa_session_key);
    let server_aes_key = String::from_utf8(buffer).unwrap();

    // assemble the two part of the aes key
    let aes_session_key = format!("{}{}", server_aes_key, client_aes_key);
    let aes_session_key: [u8; 16] = aes_session_key
        .as_bytes()
        .try_into()
        .expect("AES session key must be 16 bytes");

    // =======================================
    // Authentification
    // =======================================

    // receive the figerprint of the server
    // and simulate the search in the known host
    let known_host = Vec::new();
    let fingerprint = receive(&mut stream, aes_session_key)?;
    if !known_host.contains(&fingerprint) {
        println!("Warning: unknown host, trust it ? Y/N");

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("failed to read the answer");
        if answer.trim() != "Y" {
            send(
                &mut stream,
                String::from_str("KO").unwrap(),
                aes_session_key,
            )?;
            return Ok(());
        }
    }

    // get the login and the password and send it to the server
    let mut login = String::new();
    let mut password = String::new();

    print!("login: ");
    io::stdout().flush().expect("failed to flush stdout");
    io::stdin()
        .read_line(&mut login)
        .expect("failed to read the login");
    print!("password: ");
    io::stdout().flush().expect("failed to flush stdout");
    io::stdin()
        .read_line(&mut password)
        .expect("failed to read the password");
    let message = format!("{}\n{}", login.trim(), password.trim());
    send(&mut stream, message, aes_session_key)?;

    let response = receive(&mut stream, aes_session_key)?;
    if response != "connected" {
        println!("Login or password unknown");
        return Ok(());
    }

    // ========================================
    // Main communication loop
    // ========================================

    loop {
        // Read the command
        print!("command: ");
        io::stdout().flush().expect("failed to flush stdout");
        let mut command = String::new();
        io::stdin()
            .read_line(&mut command)
            .expect("failed to read the command");

        // send the command to the server
        send(&mut stream, command.clone(), aes_session_key)?;

        // print the server answer
        let answer = receive(&mut stream, aes_session_key)?;
        println!("{answer}");

        if command.trim() == "exit" {
            break;
        }
    }

    Ok(())
}
