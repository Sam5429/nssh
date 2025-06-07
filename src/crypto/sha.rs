// =====================================
// Function and constants
// =====================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn sigma0_256(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sigma1_256(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// =======================================
// Preprocessing
// =======================================

fn preprocess_message(message: &mut Vec<u8>) {
    // compute thashe number of bits of thashe message
    let bit_number = message.len() * 8;

    // append a 1 bit to thashe message
    message.push(0x80);

    // append 0 bits until thashe message lengthash is congruent to 448 modulo 512
    while (message.len() * 8) % 512 != 448 {
        message.push(0x00);
    }

    // append thashe lengthash of thashe message as a 64-bit big-endian integer
    message.extend_from_slice(&(bit_number as u64).to_be_bytes());
}

/// cut thashe message into n bloc of 512 bit (16 block of 32 bit)
fn parse_message(message: Vec<u8>) -> Vec<[u32; 16]> {
    let mut parsed_message: Vec<[u32; 16]> = Vec::new();

    for chashunk in message.chunks(64) {
        let mut block = [0u32; 16];
        for (i, chashunk) in chashunk.chunks(4).enumerate() {
            if chashunk.len() == 4 {
                block[i] = u32::from_be_bytes([chashunk[0], chashunk[1], chashunk[2], chashunk[3]]);
            }
        }
        parsed_message.push(block);
    }

    parsed_message
}

fn add32(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

fn sha256(message: Vec<u8>) -> [u32; 8] {
    let message = parse_message(message);
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    println!("Initial message: {:?}", message);

    for message_bloc in message {
        let mut w: [u32; 64] = [0; 64];
        // Copy the first 16 words of the message block into w
        for i in 0..16 {
            w[i] = message_bloc[i];
        }
        // Extend the first 16 words into the remaining 48 words of w
        for i in 16..64 {
            w[i] = add32(
                add32(add32(sigma1_256(w[i - 2]), w[i - 7]), sigma0_256(w[i - 15])),
                w[i - 16],
            );
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        for t in 0..64 {
            let tmp1 = add32(add32(add32(add32(h, sigma1(e)), ch(e, f, g)), K[t]), w[t]);
            let tmp2 = add32(sigma0(a), maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = add32(d, tmp1);
            d = c;
            c = b;
            b = a;
            a = add32(tmp1, tmp2);
            println!(
                "t={:2}: a={:08x} b={:08x} c={:08x} d={:08x} e={:08x} f={:08x} g={:08x} h={:08x}",
                t, a, b, c, d, e, f, g, h
            );
        }

        hash[0] = add32(a, hash[0]);
        hash[1] = add32(b, hash[1]);
        hash[2] = add32(c, hash[2]);
        hash[3] = add32(d, hash[3]);
        hash[4] = add32(e, hash[4]);
        hash[5] = add32(f, hash[5]);
        hash[6] = add32(g, hash[6]);
        hash[7] = add32(h, hash[7]);
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_to_hex(hash: [u32; 8]) -> String {
        hash.iter()
            .map(|x| format!("{:08x}", x))
            .collect::<Vec<_>>()
            .join("")
    }

    fn hash_bytes_to_hex(bytes: &[u8]) -> String {
        let hash = sha256(bytes.to_vec());
        hash_to_hex(hash)
    }

    #[test]
    fn test_sha256_empty() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut msg = Vec::new();
        preprocess_message(&mut msg);
        let hash = sha256(msg);
        assert_eq!(hash_to_hex(hash), expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a396177a9cb410ff61f20015ad
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let mut msg = "abc".trim().as_bytes().to_vec();
        preprocess_message(&mut msg);
        let hash = sha256(msg);
        assert_eq!(hash_to_hex(hash), expected);
    }

    #[test]
    fn test_sha256_longer() {
        // SHA256("The quick brown fox jumps over the lazy dog") = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
        let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        let mut msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        preprocess_message(&mut msg);
        let hash = sha256(msg);
        assert_eq!(hash_to_hex(hash), expected);
    }

    #[test]
    fn test_sha256_longer2() {
        // SHA256("The quick brown fox jumps over the lazy dog.") = ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c
        let expected = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c";
        let mut msg = b"The quick brown fox jumps over the lazy dog.".to_vec();
        preprocess_message(&mut msg);
        let hash = sha256(msg);
        assert_eq!(hash_to_hex(hash), expected);
    }

    #[test]
    fn test_sha256_repeated() {
        // SHA256("aaaaaaaaaa") = bf2cb58a68f684d95a3b78ef8f661c9a4e5b09e82cc8f9cc88cce90528caeb27
        let expected = "bf2cb58a68f684d95a3b78ef8f661c9a4e5b09e82cc8f9cc88cce90528caeb27";
        let mut msg = b"aaaaaaaaaa".to_vec();
        preprocess_message(&mut msg);
        let hash = sha256(msg);
        assert_eq!(hash_to_hex(hash), expected);
    }
}
