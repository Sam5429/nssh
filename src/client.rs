use crate::crypto::aes;
use crate::crypto::rsa;
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
    println!("private key : {:?}", rsa_session_key);
    println!("aes key : {:?}", client_aes_key);

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
    println!("server aes key : {:?}", server_aes_key);

    // assemble the two part of the aes key
    let aes_session_key = format!("{}{}", server_aes_key, client_aes_key);
    let aes_session_key: [u8; 16] = aes_session_key
        .as_bytes()
        .try_into()
        .expect("AES session key must be 16 bytes");
    println!("server public key : {:?}", server_pub_key);
    println!("aes session key : {:?}", aes_session_key);

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

    println!("login: ");
    io::stdin()
        .read_line(&mut login)
        .expect("failed to read the login");
    println!("password: ");
    io::stdin()
        .read_line(&mut password)
        .expect("failed to read the password");
    let message = format!("{}\n{}", login.trim(), password.trim());
    send(&mut stream, message, aes_session_key)?;

    let response = receive(&mut stream, aes_session_key)?;
    println!("{response}");
    // Read the public key of the server
    // let mut rsa_public_key_buff = [0,8];
    // stream.read(&mut rsa_public_key_buff).unwrap();
    // let n = u32::from_be_bytes(rsa_public_key_buff[..4]);
    // let e = u32::from_be_bytes(rsa_public_key_buff[4..8]);
    // let server_public_key = rsa::PublicKey::new(n, e);

    // // tcheck if the host if known
    // let known_host: Vec<rsa::PublicKey>= Vec::new();
    // if !known_host.contains(&server_public_key) {
    //     println!("Unknown host are you trusting this server: {}", stream.local_addr().unwrap());
    //     let mut answer = String::new();
    //     io::stdin().read_line(&mut answer).expect("failed to read the answer");
    //     if answer == "Y" {
    //         known_host.append(&server_public_key);
    //     } else {
    //         return Ok(());
    //     }
    // }

    // // ===========================================
    // // Get the aes key to start the crypted communication
    // // ===========================================

    // // ==========================================
    // // Identification of the user
    // // ============================================

    // // récup la clé public de l'autre plus la clé aes
    // stream.read(&mut buffer).unwrap();

    // // déchiffre avec sa clé privé
    // let aes_key: [u8; 16] = rsa::decypher_message(Vec::from(buffer), private_key)
    //     .try_into()
    //     .unwrap();

    // println!("Received :");
    // println!("AES Key: {:?}", aes_key);

    // loop {
    //     print!("Enter message: ");
    //     io::stdout().flush()?;

    //     let mut input = String::new();
    //     io::stdin().read_line(&mut input)?;

    //     if input.trim() == "exit" {
    //         break;
    //     }

    //     let crypted_input = aes::cypher_message(Vec::from(input), aes_key);
    //     stream.write(&crypted_input).unwrap();
    //     let bytes_read = stream.read(&mut buffer).unwrap();
    //     let decypher_request = aes::decypher_message(Vec::from(&buffer[..bytes_read]), aes_key);
    //     let response = String::from_utf8(decypher_request).unwrap();
    //     println!("Server response: {}", response);
    // }

    Ok(())
}
