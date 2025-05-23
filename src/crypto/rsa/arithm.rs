use rand::Rng;

struct CoefEb {
    a: u32,
    b: u32,
    u: i32,
    v: i32,
    gcd: u32,
}

// find the euclid bezout coeficient for a and b
fn bezout(mut a: u32, mut b: u32) -> CoefEb {
    let mut coef_eb = CoefEb {
        a,
        b,
        u: 0,
        v: 1,
        gcd: b,
    };
    let mut reste: u32;
    let mut u: i32 = 0;
    let mut u1: i32 = 0;
    let mut u2: i32 = 1;
    let mut v: i32 = 1;
    let mut v1: i32 = 1;
    let mut v2: i32 = 0;

    reste = coef_eb.a % coef_eb.b;
    while reste != 0 {
        u = u2 - (a / b) as i32 * u1;
        v = v2 - (a / b) as i32 * v1;

        a = b;
        b = reste;
        reste = a % b;

        u2 = u1;
        u1 = u;
        v2 = v1;
        v1 = v;
    }
    coef_eb.gcd = b;
    coef_eb.u = u;
    coef_eb.v = v;
    coef_eb
}

// find the modular inverse of a modulo n
pub fn modular_inv(a: u32, n: u32) -> u32 {
    let coef_eb = bezout(a, n);

    // tchek if the pgc differ from 1
    if coef_eb.gcd != 1 {
        panic!("gcd(a, n) != 1");
    }

    // return the positif modular inverse
    if coef_eb.u > 1 {
        return coef_eb.u as u32;
    }
    // ! BUG : il y a moyen que ca fasse un overflow
    (coef_eb.u as i64 + n as i64) as u32
}

// find a coprime of n
pub fn find_coprime(n: u32) -> u32 {
    for i in 2..n {
        let coef_eb = bezout(i, n);
        if coef_eb.gcd == 1 {
            return i;
        }
    }
    return u32::MAX;
}

pub fn fast_exp(mut base: u32, mut exp: u32, modulus: u32) -> u32 {
    let mut result = 1;

    while exp > 0 {
        if exp % 2 == 1 {
            result = ((result as u64 * base as u64) % modulus as u64) as u32;
        }
        base = ((base as u64 * base as u64) % modulus as u64) as u32;
        exp /= 2;
    }
    result
}

/// test if a is a witness of the primness of n
/// n-1=m*2^s, with m odd
fn mr_witness(n: u32, m: u32, s: u32, a: u32) -> bool {
    // test a^m = 1[n]
    if fast_exp(a, m, n) == 1 {
        return true;
    }
    // test a^(2^j*m) = -1[p]
    for j in 1..s {
        if fast_exp(a, (1 << j) * m, n) == n - 1 {
            return true;
        }
    }
    false
}

/// test nb_witness random witness for the primeness of n
pub fn mr_test(n: u32, nb_witness: u32) -> bool {
    let mut s = 0;

    // find s and m with n-1 = 2^s*m with m odd
    let mut tmp = n - 1;
    while tmp % 2 == 0 {
        tmp /= 2;
        s += 1;
    }
    let m = tmp;

    for _ in 0..nb_witness {
        let witness = rand::random();
        if !mr_witness(n, m, s, witness) {
            return false;
        }
    }

    true
}

/// create a randon number with k binary digits
fn create_number(k: u32) -> u32 {
    // set the most significant bit to 1
    let mut number = 1;

    // generate random bits
    let mut rng = rand::rng();
    for _ in 1..k {
        number <<= 1;
        number |= rng.random::<u32>() % 2;
    }
    number
}

/// create a random prime numbel with k binary digits
/// and with a proba below epsilon that he is not prime
pub fn mr_prime(k: u32, epsilon: f64) -> u32 {
    loop {
        let suspect = create_number(k);

        // compute the number of witness needed to have more than a epsilon proba of being prime
        // one witness has a proba of 1/4 to lie
        let mut nb_witness = 1;
        let mut lie_prob = 1.0 / 4.0;
        while 1.0 - lie_prob < epsilon {
            nb_witness += 1;
            lie_prob *= 1.0 / 4.0;
        }

        let is_prime = mr_test(suspect, nb_witness);

        if is_prime {
            return suspect;
        }
    }
}
