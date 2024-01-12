use xwing_kem::{XwingKeyPair, XwingCiphertext};

fn main() {
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