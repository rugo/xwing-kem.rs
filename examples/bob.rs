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
    let ss_val = ss_result.to_bytes();

    assert_eq!(&ss.to_bytes(), &ss_val);

    println!("Shared secret is: {:x?}", ss_val)
}