/**
# Full Signature
## Sign a message with your private key

- Receive a message like bytes and return a signature like bytes
- It is possible to decode the signature back to the message
- (64 + message length) byte signature
- Slow to sign and verify

## Example

```rust
use ed25519_axolotl::crypto::signatures::validate_signature;
use ed25519_axolotl::crypto::signatures::full_signature;
use ed25519_axolotl::utils::random::random_bytes;
use ed25519_axolotl::crypto::keys::KeyPair;

let keys = KeyPair::new(Some(vec![1; 32]));
let msg = "Lunes"
    .as_bytes()
    .iter()
    .map(|x| *x as u32)
    .collect::<Vec<u32>>();
let signature = full_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

assert_eq!(true, validate_signature(keys.pubk, msg, signature));
```
*/
pub fn full_signature(
    secret_key: Vec<u32>,
    message: Vec<u32>,
    opt_random: Option<Vec<u32>>,
) -> Vec<u32> {
    use crate::utils::extras::curve25519_sign;
    use crate::utils::random::random_bytes;

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

/**
# Fast Signature
## Sign a message with your private key

- Receive a message like bytes and return a signature like bytes
- Don't possible to decode signature back to message
- Quick to sign and verify
- 64 byte signature

# Example

```rust
use ed25519_axolotl::crypto::signatures::validate_signature;
use ed25519_axolotl::crypto::signatures::fast_signature;
use ed25519_axolotl::utils::random::random_bytes;
use ed25519_axolotl::crypto::keys::KeyPair;

let keys = KeyPair::new(Some(vec![1; 32]));
let msg = "Lunes"
    .as_bytes()
    .iter()
    .map(|x| *x as u32)
    .collect::<Vec<u32>>();
let signature = fast_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

assert_eq!(true, validate_signature(keys.pubk, msg, signature));
```
*/
pub fn fast_signature(
    secret_key: Vec<u32>,
    message: Vec<u32>,
    opt_random: Option<Vec<u32>>,
) -> Vec<u32> {
    use crate::utils::extras::curve25519_sign;
    use crate::utils::random::random_bytes;

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

/**
# Validate Signature
## Validate a signature with a message and your public key

- Receive a public key, message, signature end return bool

## Example

```rust
use ed25519_axolotl::crypto::signatures::validate_signature;
use ed25519_axolotl::crypto::signatures::fast_signature;
use ed25519_axolotl::utils::random::random_bytes;
use ed25519_axolotl::crypto::keys::KeyPair;

let keys = KeyPair::new(Some(vec![1; 32]));
let msg = "Lunes"
    .as_bytes()
    .iter()
    .map(|x| *x as u32)
    .collect::<Vec<u32>>();
let signature = fast_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

assert_eq!(true, validate_signature(keys.pubk, msg, signature));
```
*/
pub fn validate_signature(public_key: Vec<u32>, message: Vec<u32>, signature: Vec<u32>) -> bool {
    use crate::utils::extras::curve25519_sign_open;

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

/**
# Decode Signature
## Decoded a Signature using your public key

- Receive a public key and signature and return a message decoded
- Possible only for full_signature function

Example

```rust
use ed25519_axolotl::crypto::keys::KeyPair;
use ed25519_axolotl::crypto::signatures::{decode_signature, full_signature};
use ed25519_axolotl::utils::random::random_bytes;

let keys = KeyPair::new(Some(vec![1; 32]));
let msg = "Lunes"
    .as_bytes()
    .iter()
    .map(|x| *x as u32)
    .collect::<Vec<u32>>();

let signature = full_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

assert_eq!(msg, decode_signature(keys.pubk, signature))
```
*/
pub fn decode_signature(public_key: Vec<u32>, signed_msg: Vec<u32>) -> Vec<u32> {
    use crate::utils::extras::curve25519_sign_open;

    let mut tmp: Vec<u32> = vec![0; signed_msg.len()];
    let mut ref_signed_msg = signed_msg.clone();

    let message_len = curve25519_sign_open(&mut tmp, &mut ref_signed_msg, public_key) as usize;
    let mut message: Vec<u32> = vec![0; message_len as usize];
    for i in 0..message_len {
        message[i] = tmp[i]
    }

    message
}
