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

#[cfg(test)]
mod test {
    use super::*;

    mod keys_generate {
        use super::KeyPair;

        #[test]
        fn test_0() {
            let seed = vec![1; 32];
            let keys = KeyPair::new(Some(seed));

            assert_eq!(
                keys.prvk,
                [
                    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 65
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
        fn test_1() {
            let seed = vec![2; 32];
            let keys = KeyPair::new(Some(seed));

            assert_eq!(
                keys.prvk,
                [
                    0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 66
                ]
            );
            assert_eq!(
                keys.pubk,
                [
                    206, 141, 58, 209, 204, 182, 51, 236, 123, 112, 193, 120, 20, 165, 199, 110,
                    205, 2, 150, 133, 5, 13, 52, 71, 69, 186, 5, 135, 14, 88, 125, 89
                ]
            );
        }

        #[test]
        fn test_2() {
            let seed = vec![3; 32];
            let keys = KeyPair::new(Some(seed));

            assert_eq!(
                keys.prvk,
                [
                    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                    3, 3, 3, 3, 3, 67
                ]
            );
            assert_eq!(
                keys.pubk,
                [
                    93, 254, 221, 59, 107, 212, 127, 111, 162, 142, 225, 93, 150, 157, 91, 176,
                    234, 83, 119, 77, 72, 139, 218, 249, 223, 28, 110, 1, 36, 179, 239, 34
                ]
            );
        }

        #[test]
        fn test_3() {
            let seed = vec![4; 32];
            let keys = KeyPair::new(Some(seed));

            assert_eq!(
                keys.prvk,
                [
                    0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                    4, 4, 4, 4, 4, 68
                ]
            );
            assert_eq!(
                keys.pubk,
                [
                    172, 1, 178, 32, 158, 134, 53, 79, 184, 83, 35, 123, 93, 224, 244, 250, 177,
                    60, 127, 203, 244, 51, 166, 28, 1, 147, 105, 97, 127, 236, 241, 11
                ]
            );
        }

        #[test]
        fn test_4() {
            let seed = vec![5; 32];
            let keys = KeyPair::new(Some(seed));

            assert_eq!(
                keys.prvk,
                [
                    0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                    5, 5, 5, 5, 5, 69
                ]
            );
            assert_eq!(
                keys.pubk,
                [
                    80, 166, 20, 9, 177, 221, 208, 50, 94, 155, 22, 183, 0, 231, 25, 233, 119, 44,
                    7, 0, 11, 27, 215, 120, 110, 144, 124, 101, 61, 32, 73, 93
                ]
            );
        }
    }

    mod signature_functions {
        use super::{fast_signature, full_signature, random_bytes, str_to_vec32, validate_signature, KeyPair};

        fn main_keys() -> KeyPair {
            KeyPair::new(Some(vec![1; 32]))
        }

        mod fast_sign_funtion {
            use super::*;
            #[test]
            fn test_0() {
                let msg = str_to_vec32("hello e25519 axolotl".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_1() {
                let msg = str_to_vec32("testing other message in signature".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_2() {
                let msg = str_to_vec32("1234567890".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_3() {
                let msg = str_to_vec32("acacacacacaca".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_4() {
                let msg = str_to_vec32("new test".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_5() {
                let msg = str_to_vec32("five test with sign function".to_string());
                let signature =
                    fast_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }
        }

        mod full_sign_function {
            use super::*;

            #[test]
            fn test_0() {
                let msg = str_to_vec32("hello e25519 axolotl".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_1() {
                let msg = str_to_vec32("testing other message in signature".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_2() {
                let msg = str_to_vec32("1234567890".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_3() {
                let msg = str_to_vec32("acacacacacaca".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_4() {
                let msg = str_to_vec32("new test".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }

            #[test]
            fn test_5() {
                let msg = str_to_vec32("five test with sign function".to_string());
                let signature =
                    full_signature(main_keys().prvk, msg.clone(), Some(random_bytes(64)));

                assert_eq!(validate_signature(main_keys().pubk, msg, signature), true)
            }
        }
    }

    mod decode_message {
        use super::*;

        #[test]
        fn test_0() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("hello e25519 axolotl".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("hello e25519 axolotl", vec32_to_str(msg));
        }

        #[test]
        fn test_1() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("testing other message in signature".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("testing other message in signature", vec32_to_str(msg));
        }

        #[test]
        fn test_2() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("1234567890".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("1234567890", vec32_to_str(msg));
        }

        #[test]
        fn test_3() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("acacacacacaca".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("acacacacacaca", vec32_to_str(msg));
        }

        #[test]
        fn test_4() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("new test".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("new test", vec32_to_str(msg));
        }

        #[test]
        fn test_5() {
            let keys = KeyPair::new(None);
            let msg = str_to_vec32("five test with sign function".to_string());

            let mut sign_msg = full_signature(keys.prvk, msg, Some(random_bytes(64)));
            let msg = decode_message(keys.pubk, sign_msg);

            assert_eq!("five test with sign function", vec32_to_str(msg));
        }
    }
}
