use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::crypto::rsa;

pub fn connect_and_communicate() -> io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    let mut buffer = [0; 512];
    let private_key = rsa::PrivateKey::generate();

    // envoie la clé public au serveur
    println!("{:?}", private_key.pub_key);

    stream.write_all(&private_key.pub_key.as_bytes())?;

    // récup la clé public de l'autre plus la clé aes
    stream.read(&mut buffer).unwrap();

    // déchiffre avec sa clé privé
    let decyphered_message = rsa::decypher_message(Vec::from(buffer), private_key);

    let n = u32::from_be_bytes([
        decyphered_message[0],
        decyphered_message[1],
        decyphered_message[2],
        decyphered_message[3],
    ]);
    let e = u32::from_be_bytes([
        decyphered_message[4],
        decyphered_message[5],
        decyphered_message[6],
        decyphered_message[7],
    ]);
    let pub_key = rsa::PublicKey::new(n, e);

    let aes_key = Vec::from(&decyphered_message[8..]);
    let aes_key_str = String::from_utf8_lossy(&aes_key);
    println!("Received :");
    println!("AES Key: {}", aes_key_str);
    println!("{:?}\n{:?}", n, e);

    loop {
        print!("Enter message: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim() == "exit" {
            break;
        }

        stream.write_all(input.as_bytes())?;
        let bytes_read = stream.read(&mut buffer)?;
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        println!("Server response: {}", response);
    }

    Ok(())
}
