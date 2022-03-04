# Curve25519 signatures like in the early Axolotl


# Rust
## Import
```rs
use ed25519_axolotl::{
    fast_signature,
    full_signature,
    decode_message,
    random_bytes,
    str_to_vec32,
    vec32_to_str,
    KeyPair
    verify,
};
```


## Generate New `KeyPair`
- the seed needs 32 bytes length or more
- if none, generate random keys
```rs
// seed: Vec<u32>
// let keys = KeyPair::new(Some(seed));

let keys = KeyPair::new(None);

println!("{}", keys);
```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature = fast_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature = full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
```

## Validate Signatures
- works with both fast and full signatures
```rs
let keys = KeyPair::new(None);


let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature_full = full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
assert_eq!(true, validate_signature(keys.pubk, msg, signature_full));

let signature_fast = fast_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
assert_eq!(true, validate_signature(keys.pubk, msg, signature_fast));
```

## Decode Message
- possible only for full_signature function
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let mut sign_msg = full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
let decoded_msg = decode_message(keys.pubk, &mut sign_msg);
```

# NodeJs (WebAssembly)
## Import
```js
import * as wasm from "ed25519_axolotl";
```
or 
```js
const wasm = require("ed25519_axolotl")
```


## Generate New `KeyPair`
- the seed needs 32 bytes length or more
- if none, generate random keys
```js
// const seed =  wasm.stringToUint32Array("your seed with 32 bytes of length or more")
// const keys = new wasm.KeyPair(seed)
const keys = new wasm.KeyPair()

```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```js
const keys = new wasm.KeyPair()

const msg = wasm.stringToUint32Array("hello lunes")
const signature = wasm.fastSignature(k.privateKey, msg, wasm.randomBytes(64))
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```js
const keys = new wasm.KeyPair()

const msg = wasm.stringToUint32Array("hello lunes")
const signature = wasm.fullSignature(k.privateKey, msg, wasm.randomBytes(64))
```


## Validate Signatures
- works with both fast and full signatures
```js
const keys = new wasm.KeyPair()
const msg = wasm.stringToUint32Array("hello lunes")

const signatureFast = wasm.fastSignature(k.privateKey, msg, wasm.randomBytes(64))
const validated = wasm.validateSignature(keys.publicKey, msg, signatureFast)

const signatureFull = wasm.fullSignature(k.privateKey, msg, wasm.randomBytes(64))
const validated = wasm.validateSignature(keys.publicKey, msg, signatureFull)
```

## Decode Message
- possible only for full_signature function
```js
const keys = new wasm.KeyPair()


const msg = wasm.stringToUint32Array("hello lunes")

const signature = wasm.fullSignature(k.privateKey, msg, wasm.randomBytes(64))

const dmsg = wasm.uint32ArrayToString(
    wasm.decode_message(k.publiKey, fl)
)
```

# Python (Cython)
## Import
```py
from ed25519_axolotl import KeyPair
from ed25519_axolotl import (
    validate_signature,
    fast_signature,
    full_signature,
    decode_message
)
```


## Generate New `KeyPair`
- the seed needs 32 bytes length or more
- if none, generate random keys
```py
# seed: bytes = [i for i in range(32)]
# keys = KeyPair( seed )
keys = KeyPair()

keys.private_key
keys.public_key
```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```py
keys = KeyPair()
message = b"hello lunes"

signature = fast_signature(keys.private_key, message, random_bytes(64))
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```py
keys = KeyPair()
message = b"hello lunes"

signature_full = full_signature(keys.private_key, message, random_bytes(64))
```

## Validate Signatures
- works with both fast and full signatures
```py
keys = KeyPair()
msg = b"hello lunes"

signatureFast = fast_signature(k.private_key, msg, random_bytes(64))
validated = validate_signature(keys.public_key, msg, signature_fast)

signatureFull = fullSignature(k.private_key, msg, random_bytes(64))
validated = validate_signature(keys.public_key, msg, signature_full)
```
## Decode Message
- possible only for full_signature function
```py
keys = KeyPair()
message = b"hello lunes"
signature_full = full_signature(keys.private_key, message, random_bytes(64))


decode_msg = decode_message(keys.public_key, signature_full)
like_string_msg   = ''.join(map(chr, decode_msg)))
like_bytes_msg    = bytes(decode_msg)
like_list_int_msg = decode_msg

```


# Credits
- Ported to Rust by Miguel Sandro Lucero, miguel.sandro@gmail.com, 2021.09.11, see [here](https://github.com/miguelsandro/curve25519-rust)

- You can use it under MIT or CC0 license.

- Curve25519 signatures idea and math by Trevor Perrin, see [here](https://moderncrypto.org/mail-archive/curves/2014/000205.html)

- Derived from axlsign.js written by Dmitry Chestnykh, see [here](https://github.com/wavesplatform/curve25519-js)
