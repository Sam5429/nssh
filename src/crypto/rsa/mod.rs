mod arithm;

use arithm::{fast_exp, find_coprime, modular_inv, mr_prime};

/***********************************
* 				RSA				   *
************************************/

#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub n: u32, // public module
    pub e: u32, // cypher exposant
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
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.e.to_be_bytes());
        bytes
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

    /// Generate a new private key with a public key
    pub fn generate() -> Self {
        let mut private_key = PrivateKey {
            p: 0,
            q: 0,
            d: 0,
            pub_key: PublicKey { n: 0, e: 0 },
        };

        private_key.p = mr_prime(16, 0.9);
        private_key.q = mr_prime(16, 0.9);

        // Ensure n has 32 binary numbers
        loop {
            if (private_key.p * private_key.q) >> 31 == 1 {
                break;
            }
            private_key.p = mr_prime(16, 0.9);
            private_key.q = mr_prime(16, 0.9);
        }

        private_key.pub_key.n = (private_key.p * private_key.q) as u32;
        let phi_n = (private_key.p - 1) * (private_key.q - 1);
        private_key.pub_key.e = find_coprime(phi_n);
        private_key.d = modular_inv(private_key.pub_key.e, phi_n);

        private_key
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
*		 Message manipulation	 *
**********************************/

fn bytes_to_blocks(bytes: Vec<u8>) -> Vec<u32> {
    bytes
        .chunks(4) // like iter but over 4 element at se same time
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

    // delete the null bytes at the end that were added during conversion to blocks
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

pub fn cypher_message(message: Vec<u8>, key: PublicKey) -> Vec<u8> {
    let blocks = bytes_to_blocks(message);
    let cyphered_blocks = cypher_blocks(blocks, key);
    blocks_to_bytes(cyphered_blocks)
}

pub fn decypher_message(message: Vec<u8>, key: PrivateKey) -> Vec<u8> {
    let blocks = bytes_to_blocks(message);
    let decyphered_blocks = decypher_blocks(blocks, key);
    blocks_to_bytes(decyphered_blocks)
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
        let decyphered_message = String::from_utf8(decypher_message(
            cypher_message(message.as_bytes().to_vec(), public_key),
            private_key,
        ))
        .unwrap_or_else(|_| {
            println!("{:?}", private_key);
            String::new()
        });

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

        let decyphered_message = String::from_utf8(decypher_message(
            cypher_message(message.as_bytes().to_vec(), public_key),
            private_key,
        ))
        .unwrap_or_else(|_| {
            println!("{:?}", private_key);
            String::new()
        });

        // Assert -> vérifie si le message est le bon
        assert_eq!(message, decyphered_message);
    }

    #[test]
    fn key_gen_rate() {
        // Arange
        let mut bad_key = 0;
        let message = "Hello, world!";

        // Act
        for _ in 0..10000 {
            let private_key = PrivateKey::generate();
            let public_key = private_key.pub_key.clone();

            String::from_utf8(decypher_message(
                cypher_message(message.as_bytes().to_vec(), public_key),
                private_key,
            ))
            .unwrap_or_else(|_| {
                bad_key += 1;
                String::new()
            });
        }

        // Assert
        assert!(bad_key as f64 / 10000 as f64 <= 0.9);
    }
}
