#![allow(unused, non_snake_case, non_upper_case_globals)]

mod utils;
use pyo3::{prelude::{pyclass, pymethods, pyfunction, pymodule, PyModule, PyResult, Python}, wrap_pyfunction};
use rand::Rng;
use utils::*;

#[pymodule]
fn ed25519_axolotl(py: Python, module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(validate_signature, module)?);
    module.add_function(wrap_pyfunction!(fast_signature, module)?);
    module.add_function(wrap_pyfunction!(full_signature, module)?);
    module.add_function(wrap_pyfunction!(decode_message, module)?);
    module.add_function(wrap_pyfunction!(random_bytes, module)?);
    module.add_class::<KeyPair>()?;
    Ok(())
}


#[pyclass]
pub struct KeyPair {
    prvk: Vec<u32>,
    pubk: Vec<u32>,
}

impl std::fmt::Display for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\x1b[1mKeyPair {{\x1b[0m
                \r\x1b[91mprivate_key: {:?}\x1b[0m
            \n\x1b[92mpublic_key: {:?}\n\x1b[0m\x1b[1m}}\x1b[0m",
            self.prvk, self.pubk
        )
    }
}

#[pymethods]
impl KeyPair {
    #[new]
    pub fn new(seed: Option<Vec<u32>>) -> KeyPair {
        let seed = match seed {
            Some(vec) => vec,
            None => random_bytes(32),
        };
        let mut sk: Vec<u32> = vec![0; 32];
        let mut pk: Vec<u32> = vec![0; 32];
        for i in 0..32 {
            sk[i] = seed.to_vec()[i];
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

    #[getter(private_key)]
    pub fn prvk(&self) -> Vec<u32> {
        return self.prvk.clone();
    }

    #[getter(public_key)]
    pub fn pubk(&self) -> Vec<u32> {
        return self.pubk.clone();
    }
}


#[pyfunction]
pub fn full_signature(
    secret_key: Vec<u32>,
    message: Vec<u32>,
    opt_random: Option<Vec<u32>>,
) -> Vec<u32> {
    match opt_random {
        Some(random) => {
            let mut buf: Vec<u32> = vec![0; 128 + message.len()];
            curve25519_sign(&mut buf, message.clone(), secret_key, random);
            (buf[0..64 + message.len()]).to_vec()
        }
        None => {
            let mut signed_msg: Vec<u32> = vec![0; 64 + message.len()];
            curve25519_sign(&mut signed_msg, message, secret_key, random_bytes(64));
            signed_msg
        }
    }
}

#[pyfunction]
pub fn fast_signature(
    secret_key: Vec<u32>,
    message: Vec<u32>,
    opt_random: Option<Vec<u32>>,
) -> Vec<u32> {
    match opt_random {
        Some(random) => {
            let mut buf: Vec<u32> = vec![0; 128 + message.len()];
            curve25519_sign(&mut buf, message, secret_key, random);

            let mut signature: Vec<u32> = vec![0; 64];
            for i in 0..signature.len() {
                signature[i] = buf[i];
            }
            signature
        }
        None => {
            let mut buf: Vec<u32> = vec![0; 64 + message.len()];
            curve25519_sign(&mut buf, message, secret_key, random_bytes(64));

            let mut signature: Vec<u32> = vec![0; 64];
            for i in 0..signature.len() {
                signature[i] = buf[i];
            }
            signature
        }
    }
}


#[pyfunction]
pub fn validate_signature(public_key: Vec<u32>, message: Vec<u32>, signature: Vec<u32>) -> bool {
    let mut sm: Vec<u32> = vec![0; 64 + message.len()];
    let mut m: Vec<u32> = vec![0; 64 + message.len()];

    for i in 0..64 {
        sm[i] = signature[i];
    }

    for i in 0..message.len() {
        sm[i + 64] = message[i]
    }

    if curve25519_sign_open(&mut m, &mut sm, public_key) < 0 {
        false
    } else {
        true
    }
}


#[pyfunction]
pub fn decode_message(public_key: Vec<u32>, full_signature: Vec<u32>) -> Vec<u32> {
    let mut tmp: Vec<u32> = vec![0; full_signature.len()];
    let message_len = curve25519_sign_open(&mut tmp, &mut full_signature.clone(), public_key) as usize;
    let mut message: Vec<u32> = vec![0; message_len as usize];
    for i in 0..message_len {
        message[i] = tmp[i]
    }

    message
}


#[pyfunction]
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

pub fn vec32_to_str(vec: Vec<u32>) -> String {
    let mut msg_8: Vec<u8> = vec![0; vec.len()];
    for i in 0..vec.len() {
        msg_8[i] = vec[i] as u8;
    }
    String::from_utf8(msg_8).expect("Found invalid UTF-8")
}
