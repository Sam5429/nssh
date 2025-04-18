mod arithm;

use std::fs::{self};

use arithm::{fast_exp, find_coprime, modular_inv, mr_prime};

/***********************************
* 				RSA				   *
************************************/

#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    n: u32, // public module
    e: u32, // cypher exposant
}

impl PublicKey {
    pub fn new(n: u32, e: u32) -> Self {
        PublicKey { n, e }
    }

    pub fn clone(&self) -> Self {
        PublicKey {
            n: self.n,
            e: self.e,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateKey {
    p: u32,
    q: u32,
    d: u32,
    pub pub_key: PublicKey,
}

impl PrivateKey {
    pub fn new(p: u32, q: u32, d: u32, pub_key: PublicKey) -> Self {
        PrivateKey { p, q, d, pub_key }
    }

    // entre 32768 et 65535
    pub fn generate() -> Self {
        let mut p = mr_prime(16, 0.9);
        let mut q = mr_prime(16, 0.9);
        //print!("{}", p);
        loop {
            if (p * q) >> 31 == 1 {
                break;
            }
            p = mr_prime(16, 0.9);
            q = mr_prime(16, 0.9);
            //println!(" {}", q);
        }
        let n = (p * q) as u32;
        // if n & (1 << 31) != 1 {
        //     println!("ca va pas marcher");
        // }
        let phi_n = (p - 1) * (q - 1);
        let e = find_coprime(phi_n);
        let d = modular_inv(e, phi_n);
        let pub_key = PublicKey::new(n, e);
        PrivateKey { p, q, d, pub_key }
    }
}

/// Cypher function of an u32 depending on the public key
fn cypher(block: u32, key: PublicKey) -> u32 {
    // block^e % n
    fast_exp(block, key.e, key.n)
}

/// Decypher function of an u32 depending on the private key
fn decypher(block: u32, key: PrivateKey) -> u32 {
    fast_exp(block, key.d, key.pub_key.n)
}

fn cypher_blocks(blocks: Vec<u32>, key: PublicKey) -> Vec<u32> {
    blocks.iter().map(|block| cypher(*block, key)).collect()
}

fn decypher_blocks(blocks: Vec<u32>, key: PrivateKey) -> Vec<u32> {
    blocks.iter().map(|block| decypher(*block, key)).collect()
}

/*********************************
*		 File manipulation	 	 *
**********************************/

pub fn file_to_bytes(path: &str) -> Vec<u8> {
    fs::read(path).unwrap()
}

pub fn bytes_to_file(bytes: Vec<u8>, path: &str) {
    fs::write(path, bytes).unwrap()
}

fn bytes_to_blocks(bytes: Vec<u8>) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut block = 0;
            for (i, &byte) in chunk.iter().enumerate() {
                block |= (byte as u32) << (i * 8);
            }
            block
        })
        .collect()
}

fn blocks_to_bytes(blocks: Vec<u32>) -> Vec<u8> {
    let mut bytes: Vec<u8> = blocks
        .iter()
        .flat_map(|block| {
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = ((block >> (i * 8)) & 0xFF) as u8;
            }
            bytes
        })
        .collect();

    // supp les octets null qui on était rajouter lors de la convertion en blocks
    bytes.truncate(
        bytes.len()
            - bytes
                .clone()
                .iter()
                .rev()
                .take_while(|&byte| *byte == 0)
                .count(),
    );
    bytes
}

pub fn cypher_file(path: &str, key: PublicKey) {
    let bytes = file_to_bytes(path);
    let blocks = bytes_to_blocks(bytes);
    let cyphered_blocks = cypher_blocks(blocks, key);
    let cyphered_bytes = blocks_to_bytes(cyphered_blocks);
    let new_path = path.replace(".txt", "_cypher.txt");
    bytes_to_file(cyphered_bytes, new_path.as_str());
}

pub fn decypher_file(path: &str, key: PrivateKey) {
    let bytes = file_to_bytes(path);
    let blocks = bytes_to_blocks(bytes);
    let decyphered_blocks = decypher_blocks(blocks, key);
    let decyphered_bytes = blocks_to_bytes(decyphered_blocks);
    let new_path = path.replace("_cypher.txt", "_decypher.txt");
    bytes_to_file(decyphered_bytes, new_path.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cypher_decipher() {
        // Arrange -> on a un message et une clé
        let message = "Hello, world!";
        let public_key = PublicKey::new(2436929723, 5);
        let private_key = PrivateKey::new(56519, 43117, 1462098053, public_key.clone());

        // Act -> chiffre et déciffre un message

        let blocks = bytes_to_blocks(message.as_bytes().to_vec());
        let cyphered_blocks = cypher_blocks(blocks, public_key);
        let decyphered_blocks = decypher_blocks(cyphered_blocks, private_key);
        let decyphered_bytes = blocks_to_bytes(decyphered_blocks);
        let decyphered_message = String::from_utf8(decyphered_bytes).unwrap();

        // Assert -> vérifie si le message est le bon
        assert_eq!(message, decyphered_message);
    }

    #[test]
    fn key_gen() {
        // Arrange -> on a un message
        let message = "Hello, world!";

        // Act -> créer une clé chiffre et déciffre un message
        let private_key = PrivateKey::generate();
        let public_key = private_key.pub_key.clone();

        let blocks = bytes_to_blocks(message.as_bytes().to_vec());
        let cyphered_blocks = cypher_blocks(blocks, public_key);
        let decyphered_blocks = decypher_blocks(cyphered_blocks, private_key);
        let decyphered_bytes = blocks_to_bytes(decyphered_blocks);
        let decyphered_message = String::from_utf8(decyphered_bytes).unwrap_or_else(|_| {
            println!("{:?}", private_key);
            String::new()
        });

        // Assert -> vérifie si le message est le bon
        assert_eq!(message, decyphered_message);
    }
}
