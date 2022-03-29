 # 📦 Ed25519 Axolotl

 Ed25519-like signatures with X25519 keys, Axolotl-style.

 ## ⚠️ Caution

 This repository is full of cryptography functions with some abstraction, be sure what you are doing

 ## 🔭 Telescope

 For the user guide and further documentation, please read
 [Telescope](https:blockchain.lunes.io/telescope)

 ## 🏗 Archtecture

 - **Utils**
     - random
         - random_bytes *usize* -> *Vec<u32>*
     - extras
         - ...
 - **Crypto**
     - keys
         - KeyPair::new *Option<Vec<u32>>* -> *KeyPair*
             - prvk -> *Vec<u32>*
             - pubk -> *Vec<u32>*
     - signatures
