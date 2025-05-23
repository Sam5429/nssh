mod crypto;

use crypto::*;

fn main() {
    // Example of a communication

    let message = "Hello, world!"; // The message to be sent

    // Generate a key pair to use to send the key session
    let private_key = rsa::PrivateKey::generate(); // Generate a private key
    let public_key = private_key.pub_key.clone(); // Get the public key from the private key

    let session_key = "qdmfQSDfkqldfqdfm mq"; // The session key to be sent and use for AES

    // Encrypt the session key with the public key (server side)
    let encrypted_session_key = rsa::cypher_message(session_key.as_bytes().to_vec(), public_key);

    // Sent the encrypted session key to the receiver with the public key

    // Decrypt the session key with the private key
    let decrypted_session_key = aes::string_to_key(
        String::from_utf8(rsa::decypher_message(
            encrypted_session_key,
            private_key.clone(),
        ))
        .unwrap()
        .as_str(),
    );

    let crypted_message = aes::cypher_message(message.as_bytes().to_vec(), decrypted_session_key);

    // Send the crypted message to the receiver

    // Decrypt the message with the session key
    let decrypted_message = String::from_utf8(aes::decypher_message(
        crypted_message,
        decrypted_session_key,
    ))
    .unwrap_or_else(|_| {
        println!("{:?}", private_key);
        String::new()
    });

    // Print the decrypted message
    println!("Decrypted message: {}", decrypted_message);
}
