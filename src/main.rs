mod rsa;

use rsa::{cypher_file, decypher_file, PrivateKey, PublicKey};

fn main() {
    let public_key = PublicKey::new(2436929723, 5);
    let private_key = PrivateKey::new(56519, 43117, 1462098053, public_key.clone());

    let args: Vec<String> = std::env::args().collect();
    // affiche le contenur de repertoir courant
    let message_path = args[1].as_str();
    match args[2].as_str() {
        "cypher" => cypher_file(message_path, public_key),
        "decypher" => decypher_file(message_path, private_key),
        _ => println!("Invalid command"),
    }
}
