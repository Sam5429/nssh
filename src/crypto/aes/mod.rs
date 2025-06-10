mod arithm;

use arithm::{cypher, decypher, key_expansion};

fn bytes_to_blocks(bytes: Vec<u8>) -> Vec<[u8; 16]> {
    bytes
        .chunks(16)
        .map(|chunk| {
            let mut block = [0u8; 16];
            for (i, &bytes) in chunk.iter().enumerate() {
                block[i] = bytes;
            }
            block
        })
        .collect()
}

fn blocks_to_bytes(blocks: Vec<[u8; 16]>) -> Vec<u8> {
    let mut bytes: Vec<u8> = blocks
        .iter()
        .flat_map(|block| block.iter())
        .cloned()
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

fn cypher_blocks(blocks: Vec<[u8; 16]>, expended_key: [u32; 44]) -> Vec<[u8; 16]> {
    blocks
        .iter()
        .map(|block| cypher(*block, &expended_key))
        .collect()
}

fn decypher_blocks(blocks: Vec<[u8; 16]>, expended_key: [u32; 44]) -> Vec<[u8; 16]> {
    blocks
        .iter()
        .map(|block| decypher(*block, &expended_key))
        .collect()
}

pub fn cypher_message(message: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    // Put the message in blocks of 16 bytes
    let mut blocks = bytes_to_blocks(message);

    // Cypher each block
    let expended_key = key_expansion(key);
    blocks = cypher_blocks(blocks, expended_key);

    // Cut down the blocks to 8 bites
    let bytes = blocks_to_bytes(blocks);
    bytes
}

pub fn decypher_message(message: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    // Put the message in blocks of 16 bytes
    let mut blocks = bytes_to_blocks(message);

    // Decypher each block
    let expended_key = key_expansion(key);
    blocks = decypher_blocks(blocks, expended_key);

    // Cut down the blocks to 8 bites
    let bytes = blocks_to_bytes(blocks);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cypher_decypher_real_key() {
        let key: i128 = 0x12341000234123456780000000000000;
        let message = "test moi ça ma gueule, je veut te voir en maillot de bain";

        // Convert the hexa key to array of 16 bytes
        let mut key_bytes = [0u8; 16];
        for i in 0..16 {
            key_bytes[i] = ((key >> ((15 - i) * 8)) & 0xFF) as u8;
        }

        // Cypher the message
        let cyphered_message = cypher_message(message.as_bytes().to_vec(), key_bytes);

        // Decypher the message
        let decyphered_message = decypher_message(cyphered_message, key_bytes);

        // Cut down the blocks to 8 bites
        assert_eq!(message.as_bytes().to_vec(), decyphered_message);
    }

    #[test]
    fn cypher_decypher_string() {
        let key = "AdfqdmFqdfqsdfqdfDFs";
        let key: [u8; 16] = key
            .as_bytes()
            .try_into()
            .expect("AES session key must be 16 bytes");
        let message = "test moi ça ma gueule, je veut te voir en maillot de bain";

        // Cypher the message
        let cyphered_message = cypher_message(message.as_bytes().to_vec(), key);

        // Decypher the message
        let decyphered_message = decypher_message(cyphered_message, key);

        // Cut down the blocks to 8 bites
        assert_eq!(message.as_bytes().to_vec(), decyphered_message);
    }
}
