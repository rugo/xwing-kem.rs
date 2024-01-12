fn main() {
    println!("Computing Keypair!");
    let (sk, pk) = xwing_kem::generate_keypair();

    println!("Encapsulating secret to be transmitted!");
    let (shared_secret, ciphertext) = xwing_kem::encapsulate(pk);

    println!("Decapsulating ciphertext with the secret key to get shared secret!");
    let computed_shared_secret = xwing_kem::decapsulate(ciphertext, sk);

    assert_eq!(shared_secret, computed_shared_secret);

    println!("Shared secret is: {:x?}", computed_shared_secret)
}