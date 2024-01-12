# Xwing KEM for Rust

This is a Rust implementation of the hybrid Xwing KEM using Kyber768 (post-quantum) and x25519 (pre-quantum).
For primitives it uses a [wrapper](https://github.com/rustpq/pqcrypto) around [PQClean](https://github.com/pqclean/PQClean/tree/0657749a785db30e7f49e9435452cb042edb1852) and [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek).

The details of Xwing are specified in the:

* [Paper](https://eprint.iacr.org/2024/039)
* [IETF Draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)

## Examples
Two examples are included, [alice](examples/alice.rs) uses Xwing directly with buffers, [bob](examples/bob.rs) uses wrapper structs.

To run an example call:

```sh
cargo run --example bob
```