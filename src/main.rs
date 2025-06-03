mod client;
mod crypto;
mod serveur;

use crypto::*;
use std::env;

fn main() {
    // launch the server or client
    if env::args().len() > 1 {
        match env::args().nth(1).as_deref() {
            Some("--serveur") => serveur::launch(),
            Some("--client") => {
                client::connect_and_communicate().expect("Failed to connect and communicate")
            }
            _ => println!("Invalid argument. Use --serveur or --client."),
        }
    } else {
        println!("Please provide an argument: --serveur or --client.");
    }
}
