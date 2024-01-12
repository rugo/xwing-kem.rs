use xwing_kem::{XwingKeyPair, XwingPublicKey};

fn main() {
    println!("Computing Keypair!");
    let keypair = XwingKeyPair::generate();

    println!("Serializing public key, because I can!");
    let pk_bytes = keypair.pk.to_bytes();

    println!("Encapsulating secret to be transmitted!");
    let pk = XwingPublicKey::from(pk_bytes);
    let (ss, ct) = pk.encapsulate();
    

    println!("Decapsulating ciphertext with the secret key to get shared secret!");
    let ss_result = keypair.sk.decapsulate(ct);

    assert_eq!(ss, ss_result);

    println!("Shared secret is: {:x?}", ss_result)
}