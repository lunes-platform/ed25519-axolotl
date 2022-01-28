#![allow(unused, non_snake_case, non_upper_case_globals)]

mod utils;
use rand::Rng;
use utils::*;

pub struct KeyPair {
    pub prvk: Vec<u32>,
    pub pubk: Vec<u32>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        KeyPair::from_seed(&random_bytes(32))
    }

    pub fn from_seed(seed: &Vec<u32>) -> KeyPair {
        let mut sk: Vec<u32> = vec![0; 32];
        let mut pk: Vec<u32> = vec![0; 32];

        for i in 0..32 {
            sk[i] = seed[i];
        }

        crypto_scalarmult_base(&mut pk, &sk);

        // Turn secret key into the correct format.
        sk[0] = sk[0] & 248;
        sk[31] = sk[31] & 127;
        sk[31] = sk[31] | 64;

        // Remove sign bit from public key.
        pk[31] = pk[31] & 127;

        KeyPair {
            prvk: sk.clone(),
            pubk: pk.clone(),
        }
    }
}

impl KeyPair {
    pub fn sign_message(
        secret_key: &Vec<u32>,
        message: &Vec<u32>,
        opt_random: &Vec<u32>,
    ) -> Vec<u32> {
        if opt_random.len() > 0 {
            let mut buf: Vec<u32> = vec![0; 128 + message.len()];
            curve25519_sign(&mut buf, &message, message.len(), secret_key, opt_random);
            let tmp: Vec<u32> = (&buf[0..64 + message.len()]).to_vec();
            return tmp;
        } else {
            let mut signed_msg: Vec<u32> = vec![0; 64 + message.len()];
            curve25519_sign(
                &mut signed_msg,
                &message,
                message.len(),
                secret_key,
                opt_random,
            );
            return signed_msg;
        }
    }

    pub fn sign(secret_key: &Vec<u32>, message: &Vec<u32>, opt_random: &Vec<u32>) -> Vec<u32> {
        let mut len = 64;
        if opt_random.len() > 0 {
            len = 128;
        }
        let mut buf: Vec<u32> = vec![0; len + message.len()];
        curve25519_sign(&mut buf, &message, message.len(), secret_key, opt_random);

        let mut signature: Vec<u32> = vec![0; 64];
        for i in 0..signature.len() {
            signature[i] = buf[i];
        }
        return signature;
    }

    pub fn open_message(public_key: &Vec<u32>, signed_msg: &mut Vec<u32>) -> Vec<u32> {
        let mut tmp: Vec<u32> = vec![0; signed_msg.len()];
        let mlen = curve25519_sign_open(&mut tmp, signed_msg, signed_msg.len(), &public_key);
        let mut m: Vec<u32> = vec![0; mlen as usize];
        for i in 0..m.len() {
            m[i] = tmp[i];
        }
        return m;
    }

    pub fn verify(public_key: &Vec<u32>, message: &Vec<u32>, signature: &Vec<u32>) -> bool {
        let mut sm: Vec<u32> = vec![0; 64 + message.len()];
        let mut m: Vec<u32> = vec![0; 64 + message.len()];

        for i in 0..64 {
            sm[i] = signature[i];
        }

        for i in 0..message.len() {
            sm[i + 64] = message[i]
        }

        let sm_len = sm.len();
        if curve25519_sign_open(&mut m, &mut sm, sm_len, &public_key) >= 0 {
            return true;
        } else {
            return false;
        }
    }
}

pub fn random_bytes(size: usize) -> Vec<u32> {
    let High: u32 = 255;
    let Low: u32 = 0;
    let mut seed: Vec<u32> = vec![0; size];
    let mut rng = rand::thread_rng();
    for i in 0..seed.len() {
        seed[i] = rng.gen_range(Low..=High);
    }
    return seed;
}

pub fn str_to_vec32(text: String) -> Vec<u32> {
    let msg: Vec<u8> = text.as_bytes().to_vec();
    let mut msg_32: Vec<u32> = vec![0; msg.len()];
    for i in 0..msg.len() {
        msg_32[i] = msg[i] as u32;
    }
    msg_32
}

pub fn vec32_to_str(vec: &Vec<u32>) -> String {
    let mut msg_8: Vec<u8> = vec![0; vec.len()];
    for i in 0..vec.len() {
        msg_8[i] = vec[i] as u8;
    }
    String::from_utf8(msg_8).expect("Found invalid UTF-8")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keys() {
        let seed = vec![1; 32];
        let keys = KeyPair::from_seed(&seed);

        assert_eq!(
            keys.prvk,
            [
                0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 65
            ]
        );
        assert_eq!(
            keys.pubk,
            [
                164, 224, 146, 146, 182, 81, 194, 120, 185, 119, 44, 86, 159, 95, 169, 187, 19,
                217, 6, 180, 106, 182, 140, 157, 249, 220, 43, 68, 9, 248, 162, 9
            ]
        );
    }

    #[test]
    fn test_sign() {
        let keys = KeyPair::new();

        let random = random_bytes(64);
        let msg = str_to_vec32("hello e25519 axolotl".to_string());
        let sign = KeyPair::sign(&keys.prvk, &msg, &random);

        let right = KeyPair::verify(&keys.pubk, &msg, &sign);
        let wrong = KeyPair::verify(&keys.prvk, &msg, &sign);

        assert_eq!(right, true);
        assert_eq!(wrong, false);
    }

    #[test]
    fn test_msg() {
        let keys = KeyPair::new();

        let random = random_bytes(64);
        let msg = str_to_vec32("hello e25519 axolotl".to_string());

        let mut sign_msg = KeyPair::sign_message(&keys.prvk, &msg, &random);
        let msg = KeyPair::open_message(&keys.pubk, &mut sign_msg);

        assert_eq!("hello e25519 axolotl", vec32_to_str(&msg));
    }
}
