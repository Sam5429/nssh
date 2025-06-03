use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::crypto::aes;
use crate::crypto::rsa;

pub fn connect_and_communicate() -> io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    let mut buffer = [0; 512];
    let private_key = rsa::PrivateKey::generate();
    println!("Private Key: {:?}", private_key);

    // envoie la clé public au serveur
    stream.write_all(&private_key.pub_key.as_bytes())?;

    // récup la clé public de l'autre plus la clé aes
    stream.read(&mut buffer).unwrap();

    // déchiffre avec sa clé privé
    let aes_key: [u8; 16] = rsa::decypher_message(Vec::from(buffer), private_key)
        .try_into()
        .unwrap();

    println!("Received :");
    println!("AES Key: {:?}", aes_key);

    loop {
        print!("Enter message: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim() == "exit" {
            break;
        }

        let crypted_input = aes::cypher_message(Vec::from(input), aes_key);
        stream.write(&crypted_input).unwrap();
        let bytes_read = stream.read(&mut buffer).unwrap();
        let decypher_request = aes::decypher_message(Vec::from(&buffer[..bytes_read]), aes_key);
        let response = String::from_utf8(decypher_request).unwrap();
        println!("Server response: {}", response);
    }

    Ok(())
}
