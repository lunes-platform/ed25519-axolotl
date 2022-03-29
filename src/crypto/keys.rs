/// # Keys for sign and validate signature
pub struct KeyPair {
    /// ## private keys for sign messages
    pub prvk: Vec<u32>,
    /// ## public keys for validate messages
    pub pubk: Vec<u32>,
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

impl KeyPair {
    /**
    ## Generate new *KeyPair*
    ```rust
    use ed25519_axolotl::crypto::keys::KeyPair;

    let keys = KeyPair::new(None);
    println!("{}", keys);
    ```
    ## Generate *KeyPair* from existent *Seed*
    ```rust
    use ed25519_axolotl::crypto::keys::KeyPair;

    let keys = KeyPair::new(Some([1;32].to_vec()));
    println!("{}", keys);
    ```
    */
    pub fn new(seed: Option<Vec<u32>>) -> KeyPair {
        use crate::utils::extras::crypto_scalarmult_base;
        use crate::utils::random::random_bytes;

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
}
