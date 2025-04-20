//mod aes;
mod rsa;

use rsa::{cypher_file, decypher_file, PrivateKey};

fn main() {
    let private_key = PrivateKey::generate();
    let public_key = private_key.pub_key.clone();

    let args: Vec<String> = std::env::args().collect();
    // affiche le contenur de repertoir courant
    let message_path = args[1].as_str();
    match args[2].as_str() {
        "cypher" => cypher_file(message_path, public_key),
        "decypher" => decypher_file(message_path, private_key),
        _ => println!("Invalid command"),
    }
}
