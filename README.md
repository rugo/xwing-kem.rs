# Xwing KEM for Rust

This is a Rust implementation of the hybrid Xwing KEM using Kyber768 (post-quantum) and x25519 (pre-quantum).
For primitives it uses a [wrapper](https://github.com/rustpq/pqcrypto) around [PQClean](https://github.com/pqclean/PQClean/tree/0657749a785db30e7f49e9435452cb042edb1852) and [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek).

The details of Xwing are specified in the:

* [Paper](https://eprint.iacr.org/2024/039)
* [IETF Draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)

## Usage
The lib exposes functions for use with buffers and some wrapper structs.

Example usage:

```rust
use xwing_kem::{XwingKeyPair, XwingCiphertext};

fn main() {
    // Using buffers
    println!("Computing Keypair!");
    let (sk, pk) = xwing_kem::generate_keypair();

    println!("Encapsulating secret to be transmitted!");
    let (shared_secret, ciphertext) = xwing_kem::encapsulate(pk);

    println!("Decapsulating ciphertext with the secret key to get shared secret!");
    let computed_shared_secret = xwing_kem::decapsulate(ciphertext, sk);
    
    // Using structs
    println!("Computing Keypair!");
    let keypair = XwingKeyPair::generate();

    println!("Encapsulating secret to be transmitted!");
    let (ss, ct) = keypair.pk.encapsulate();

    println!("Serializing ciphertext to be transmitted!");
    let ct_bytes = ct.to_bytes();

    println!("Deserializing ciphertext!");
    let ct_res = XwingCiphertext::from(ct_bytes);
    
    println!("Decapsulating ciphertext with the secret key to get shared secret!");
    let ss_result = keypair.sk.decapsulate(ct_res);

    assert_eq!(ss, ss_result);

    println!("Shared secret is: {:x?}", ss_result)
}
```

## Examples
Two examples are included, [alice](examples/alice.rs) uses Xwing directly with buffers, [bob](examples/bob.rs) uses wrapper structs.

To run an example call:

```sh
cargo run --example bob
```