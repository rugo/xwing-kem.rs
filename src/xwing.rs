use x25519_dalek::{StaticSecret as X25519SecretKey, EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey};
use pqcrypto_kyber::{kyber768, ffi::{PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES}};
use pqcrypto_traits::kem::{SecretKey as KemSecretKey, PublicKey as KemPublicKey, SharedSecret as KemSharedSecret, Ciphertext as KemCiphertext};
use sha3::{Digest, Sha3_256};
use arrayref::array_ref;


const XWING_LABEL: &[u8] = b"\\.//^\\";
const KYBER_SK_BYTES: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;
const KYBER_PK_BYTES: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
const KYBER_CT_BYTES: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
const KYBER_SS_BYTES: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES;


const X25519_SK_BYTES: usize = 32;
const X25519_PK_BYTES: usize = 32;
const X25519_CT_BYTES: usize = 32;
const X25519_SS_BYTES: usize = 32;

const XWING_SK_BYTES: usize = KYBER_SK_BYTES + X25519_SK_BYTES;
const XWING_PK_BYTES: usize = KYBER_PK_BYTES + X25519_PK_BYTES;
const XWING_CT_BYTES: usize = KYBER_CT_BYTES + X25519_CT_BYTES;
const XWING_SS_BYTES: usize = 32;  // Sha3_256 output size


pub fn generate_keypair() -> ([u8; XWING_SK_BYTES], [u8; XWING_PK_BYTES]) {
    
    let (pk_kyber, sk_kyber) = kyber768::keypair();

    let sk_x25519 = X25519SecretKey::random();
    let pk_x25519 = X25519PublicKey::from(&sk_x25519);

    let mut xwing_sk= [0u8; XWING_SK_BYTES];
    let mut xwing_pk =  [0u8; XWING_PK_BYTES];

    xwing_sk[..KYBER_SK_BYTES].copy_from_slice(sk_kyber.as_bytes());
    xwing_sk[KYBER_SK_BYTES..].copy_from_slice(sk_x25519.as_bytes());

    xwing_pk[..KYBER_PK_BYTES].copy_from_slice(pk_kyber.as_bytes());
    xwing_pk[KYBER_PK_BYTES..].copy_from_slice(pk_x25519.as_bytes());

    return (xwing_sk, xwing_pk)
}


fn combiner(ss_kyber: &[u8; KYBER_SS_BYTES], ss_x25519: &[u8; X25519_SS_BYTES], ct_x25519: &[u8; X25519_CT_BYTES], pk_x25519: &[u8; X25519_PK_BYTES]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    hasher.update(XWING_LABEL);
    hasher.update(ss_kyber);
    hasher.update(ss_x25519);
    hasher.update(ct_x25519);
    hasher.update(pk_x25519);

    hasher.finalize().try_into().unwrap()
}


pub fn encapsulate(pk: [u8; XWING_PK_BYTES]) -> ([u8; XWING_SS_BYTES], [u8; XWING_CT_BYTES]) {
    let pk_kyber = &pk[..KYBER_PK_BYTES];
    let pk_kyber = KemPublicKey::from_bytes(pk_kyber).unwrap();

    let pk_x25519 = *array_ref![&pk[KYBER_PK_BYTES..], 0, X25519_PK_BYTES];


    let tmp_x25519 = X25519EphemeralSecret::random();
    let ct_x25519 = X25519PublicKey::from(&tmp_x25519).to_bytes();
    let ss_x25519 = tmp_x25519.diffie_hellman(&X25519PublicKey::from(pk_x25519));

    let (ss_kyber, ct_kyber) = kyber768::encapsulate(&pk_kyber);

    let xwing_ss = combiner(
        ss_kyber.as_bytes().try_into().unwrap(), 
        ss_x25519.as_bytes(), 
        &ct_x25519, 
        &pk_x25519
    );

    let mut xwing_ct = [0u8; XWING_CT_BYTES];
    xwing_ct[..KYBER_CT_BYTES].copy_from_slice(ct_kyber.as_bytes());
    xwing_ct[KYBER_CT_BYTES..].copy_from_slice(&ct_x25519);

    (xwing_ss, xwing_ct)
}


pub fn decapsulate(ct: [u8; XWING_CT_BYTES], sk: [u8; XWING_SK_BYTES]) -> [u8; 32] {
    let ct_kyber = &ct[..KYBER_CT_BYTES];
    let ct_x25519 = *array_ref![&ct[KYBER_CT_BYTES..], 0, X25519_CT_BYTES];

    let sk_kyber = &sk[..KYBER_SK_BYTES];
    let sk_x25519 = &sk[KYBER_SK_BYTES..];

    let pk_x25519 = X25519PublicKey::from(
        &X25519SecretKey::from(*array_ref![sk_x25519, 0, X25519_SK_BYTES])
    ).to_bytes();

    let ss_kyber = kyber768::decapsulate(
        &KemCiphertext::from_bytes(ct_kyber).unwrap(), 
        &KemSecretKey::from_bytes(sk_kyber).unwrap()
    );


    let sk_x25519 = X25519SecretKey::from(*array_ref![sk_x25519, 0, X25519_SK_BYTES]);
    let ss_x25519 = sk_x25519.diffie_hellman(&X25519PublicKey::from(ct_x25519));

    combiner(
        ss_kyber.as_bytes().try_into().unwrap(), 
        ss_x25519.as_bytes(), 
        &ct_x25519,
        &pk_x25519
    )
}


#[derive(PartialEq, Eq)]
pub struct XwingSecretKey([u8; XWING_SK_BYTES]);

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct XwingPublicKey([u8; XWING_PK_BYTES]);

#[derive(PartialEq, Eq, Debug)]
pub struct XwingSharedSecret([u8; XWING_SS_BYTES]);

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct XwingCiphertext([u8; XWING_CT_BYTES]);

pub struct XwingKeyPair {
    pub sk: XwingSecretKey,
    pub pk: XwingPublicKey
}

impl XwingSecretKey {
    pub fn decapsulate(&self, ct: XwingCiphertext) -> XwingSharedSecret {
        XwingSharedSecret(decapsulate(ct.0, self.0))
    }

    pub fn from(bytes: [u8; XWING_SK_BYTES]) -> XwingSecretKey {
        XwingSecretKey(bytes)
    }
}

impl XwingPublicKey {
    pub fn encapsulate(&self) -> (XwingSharedSecret, XwingCiphertext) {
        let (ss, ct) = encapsulate(self.0);
        (XwingSharedSecret(ss), XwingCiphertext(ct))
    }

    pub fn to_bytes(self) -> [u8; XWING_PK_BYTES] {
        self.0
    }

    pub fn from(bytes: [u8; XWING_PK_BYTES]) -> XwingPublicKey {
        XwingPublicKey(bytes)
    }
}

impl XwingSharedSecret {
    pub fn to_bytes(&self) -> [u8; XWING_SS_BYTES] {
        self.0
    }
}

impl XwingCiphertext {
    pub fn to_bytes(&self) -> [u8; XWING_CT_BYTES] {
        self.0
    }

    pub fn from(bytes: [u8; XWING_CT_BYTES]) -> XwingCiphertext {
        XwingCiphertext(bytes)
    }
}

impl XwingKeyPair {
    pub fn generate() -> XwingKeyPair {
        let (sk, pk) = generate_keypair();

        XwingKeyPair{
            sk: XwingSecretKey(sk), 
            pk: XwingPublicKey(pk)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_combiner() {
        let ss_m = [0x37u8; 32];
        let ss_x = [0x38u8; 32];
        let ct_x = [0x39u8; 32];
        let pk_x = [0x40u8; 32];

        let result = [228, 196, 54, 163, 34, 255, 199, 110, 124, 74, 193, 167, 67, 59, 134, 255, 182, 126, 43, 213, 94, 93, 232, 173, 142, 104, 254, 109, 31, 102, 225, 213];

        assert_eq!(combiner(&ss_m, &ss_x, &ct_x, &pk_x), result);
    }


    #[test]
    fn test_encaps_decaps() {
        let (sk, pk) = generate_keypair();

        let (ss, ct) = encapsulate(pk);

        let ss2 = decapsulate(ct, sk);

        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_encaps_decaps_structs() {
        let keypair = XwingKeyPair::generate();

        let (ss, ct) = keypair.pk.encapsulate();

        let computed_ss = keypair.sk.decapsulate(ct);

        assert_eq!(computed_ss.to_bytes(), ss.to_bytes())
    }

    #[test]
    fn test_to_from() {
        let keypair = XwingKeyPair::generate();

        let pk = XwingPublicKey::from(keypair.pk.to_bytes());

        let (ss, ct) = pk.encapsulate();

        let ct = XwingCiphertext::from(ct.to_bytes());

        let ss_result = keypair.sk.decapsulate(ct);

        assert_eq!(ss_result.to_bytes(), ss.to_bytes())
    }

    #[test]
    fn test_vecs() {
        let sk = hex::decode("24c59d1c7603e7b74bc7aa1bc2cb3a214b3cfaebb63bd85b65408427c498ba394371bb271f92a3b
        506b81d54a95a7c0ddfbaa1519553d6f3cd5a601b7db6b0e91a5149468f1f68ad26478bf3c6670e093ac4c49e7a90ba46595de94c50e04129a81
        1a841b39534a87f0ae7b1116553e20c9a566b9b8ff7c7e728b8b201893403a4f252a55230874c256b897834cda349807b25cbd75a30867bfb803
        28200017f1cb70b56cc546b65d3dc9cdb45107cf10dba349619043ac35c0b9546309a239039813ed5c40f353a5e8e42193564496112bda56cb38
        c081df252ae9c2c7e441a062e92a7c8da7a240c9952d86b5f1bb6a53b38a5ac0a54a84b43f12da1d0525655684a12090b60b28b0c628db092015
        547d1070af5d6192e639636615d03c654bb90008ca15b784119f6178a00d7bef4a54a274ac922e55c61a3a8840aa258639484a3bce2e43b6c969
        b11275631daa129a61ea0e2939f0877e1a110c8a44b24c54fbb07a958db9feeca1eb52b086c87bf43a9b02a5b2c4762117c3a99ae4c4e2eaa7a3
        3b9a714737215c10317514f6c4299ef92acd64c4858e85ce737a801890022d7381f3540230c0c8ef50a848a28b09ba0bf8b50619c905751601d7
        629767449c9c0b2bae321f438a77f412a55e45ecab4b39053c6561801c639be6495be8fa144ef6029af663407ca9181946de5f3aec7236343ab3
        bc5a38a09c01b412baf0afb23f9e9b8f2b40810f2ce4ffbcdbfd87972323e98065160bcba34b3afd6c25b664745fca99a9ea75cef019d768485e
        c23336d9b39e4d05d8d587b30633d4f69ade5753a39680235e44f27995da96798f3a85e184a9fad19320829629f4140417bb7dbf5851ab792581
        34146d088452774991a087a1c2beaea89f218087ba774ae253b494c27750b1de04b44d953c5e47ab10f65205ee212f9c30391e52995539549168
        73a0b41164543e801c0b099cb44f48995675823c10b40f4bbac9177a558ca0c30765c2aabfd6a4da54c8413e33902d63f064330f0464982429de
        2604cd03b4de84a9f821a5470423a40a964dcc41863363d77b02c3127304f942ee71c98c643a427533ef300104948b825277953aaabfd855588f
        75a77d199a213ad348116e9e539f6d37068a551c710548b7a2c7ee95f9cd9b3483332673cc44bcb18a778a49455c768e0b340f81102ac6b76b06
        4057151ef101ae143787f548553558df8035a3ce00c9c43cda43142cca39034b09a7e6089867b4c64980a69ecab2e6818724c35cb909d5d45bc6
        a349c71b306567664adc0cc8ef698049b4b4b432dd0f69fac07580f77c4f79b22bb90cb97b341880716853431694c9120f6724ad58d57127fced
        999ff6229a5d4c3c240129cc812acc73698f949d8e73661f2528262bfccfa5cdf5a2104649806e295ea161217083365aa26cee6ae2f1356e8e1c
        5cefcc85703447ef1160a1b4a0e8c017b173802c66c88ab70d39a6c96c1569d5a86245a7eeb087d682219080768745b44bf244f65b567b2658db
        ae6962ba52b322118e214cfadd7cf3502582dc9cafba952a9637ad3600710259778d99d23f8235da90791604b4f0a4f7640680f59b633d93dfb8
        4282ba54c674b115684a41bc331b659a61a04883d0c5ebbc0772754a4c33b6a90e52e0678ce06a0453ba8a188b15a496bae6a24177b636d12fbb
        088f2cd9504ac200231473031a31a5c62e46288fb3edb858b21bc0ea59a212fd1c6dba09e920712d068a2be7abcf4f2a3533443ee1780dd41968
        1a960cd90af5fcaab8c1552ef25572f157a2bbb934a18a5c57a761b54a45d774ac6bc593583a1bcfc4dcd0cca87ab9cff463dc5e80ebbb501d18
        c8b39e324dbd07ca06cbf75ba33297abcc7aabdd5b308401ba387f533f3927b51e91380f5a59b119e354835ab182db62c76d6d85fa63241743a5
        2012aac281222bc0037e2c493b4777a99cb5929aba155a006bc9b461c365fa3583fac5414b403af9135079b33a10df8819cb462f067253f92b3c
        45a7fb1c1478d4091e39010ba44071019010daa15c0f43d14641a8fa3a94cfaa2a877ae8113bbf8221ee13223376494fb128b825952d5105ae41
        57dd6d70f71d5bd48f34d469976629bce6c12931c88ca0882965e27538f272b19796b251226075b131b38564f90159583cd9c4c3c098c8f06a26
        7b262b8731b9e962976c41152a76c30b502d0425635357b43cd3a3ecef5bc9910bb89ca9e91ba75e8121d53c2329b5222df12560d242724523ff
        60b6ead310d99954d483b91383a726a937f1b60b474b22ea5b81954580339d81c9f47bab44a3fe0c833a7dba1f5b33a5a2a459812645c6537c23
        17163d71b7bd7a4a5459a28a1c28659aad9a1ca9a99a363062d453355108445a673438e77624e73757c1a84d031cf0fb24b1187aafbe6738e9ab
        af5b42b004b1fa0d96426d3c5324235dd871e7a89364d335ebb6718ad098154208b143b2b43eb9e5fd8816c5225d494b40809b2459903c6486a1
        db9ac3414945e1867b5869c2f88cf9edc0a216681804578d34923e5a353babba923db907725b384e74e66987292e007e05c6766f267f839b7617
        c55e28b0fa2121da2d037d6830af9d869e1fb52b0cb645fe221a79b2a46e41980d34671ccc58d8756054b2cca7b13715a05f3925355cca838ab8
        d2425255f61135727167ad6bcb0632ebf86384b950ad21088c292b4a4fcc0e59c42d3f77fac85cd9f5cb049b3a29505a984c4c6ac98ca3d0a8f3
        0d2b1bd9815b94b27051b40ffc3455a668b9e141428611b280c1b8f2b55f6eb04e10c68f1340ef1582115f10ee2b785b7ebb0ec3a0c61670cf48
        107b594cd6e238e0d68961b47983b87879771519d2b7c21681cd494b420f03d004bb06eeb54f9c080c2f2aff6759074d5b3a3b11c73f1af6dc87
        4eeec254d5409fceaa90ff66d90b6930a540fd1d9be1844af1d861ff96a611a414a6c61a78fb2a78e74383ab05ebc73855a818a627242d523a3e
        2a35ab4285b4a2564f76772aaf8cdc9f87c65f1b4b5819905fb4f9ea59166fbbdb201c5eefc0df7418ca211b5b079a511b8b94429847b537fbed
        82d57632d63e815d8212d8a280d43328604a6c4d2c1887e7ab061f120a0168db2f4735369b193780f0aeb381ff2653f3b46e206afe77a7e814c7
        716a1b166727dd2a0b9a7d8aeace425da63977f8103457c9f438a2676c10e3a9c630b855873288ee560ca05c37cc7329e9e502cfac918b942054
        4445d4cfa93f56ee922c7d660937b5937c3074d62968f006d1211c60296685953e5def3804c2dad5c36180137c1df12f31385b670fde5cfe7644
        7f6c4b5b50083553c3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab9
        16a58d974918835d25e6a435085b2".replace("\n", "").replace(" ", "")).unwrap();
        let ct = hex::decode("718ad10318b367fc4390f63147fa5250ef61b65384a563f2c7951b2d45881fcf9f446ddd4443417eed0c001e635a994cda366f118bdd1cf0be04
        17abd1b615cc669e1b949280e28f52d3d5035c6420ff6c943421ee7589e681828c95942d4f9968f32b9ad30cccff0d98fa84b187164530dc83f9
        cde75ab1958c22dbff8af921c9ebc678a658b69663f72e7c1632b6ac8ddcbc6c8a06c3316b1aefdd07989ef944fc51406e12db6865344e03f447
        520d50c93fab1513d80cbc836950e2b52f424bb46155ba4c2e21ec5dff762bf7e92e54e0fb7618e73072607ba03b1de16f109e22dd5832a7eadf
        eb2ef00244bbaf930106cbcd2ab008f468de6d98632e9e225091a010e361ce751d633e6c37ba2530bca6fbe9d2e5348e4e168e154922992aef45
        a265ec649ce21480504b609ad5f1b0b094b74d55aaea60b8f71398cd9340802e91415937ffaa482c6678f8421c63583e8acd8d00bf285b52a26f
        a577aed109acd94ef7559554aa378f87283a7ee94af98e21a6fbac8802336ff980e15e498042a8148b69e1d8aab0b7126d0b885f9a57c1ea83ef
        cce8dccfee076dbc2f9c074525ed4e7472c3e09a9f1c50ff511150159c1be7730686c04e46368e37f2e8c82b8436463445b0edaefab876731497
        abcc563b1978eac34cf73b5b213549d1f74271d48f6a085155acd8d7db739ce6e70ad25ee636231e4151725d55ea781d483e54850e1ebda40127
        6616e7a62b22efa2e3098a006dfacaa1fca54ade6a119f3a215b523210164a7f299d2c7b8ad8a637bc1fba56de28ffa800b522246dbec7148ced
        56ed292c7d92004065598bc573dd30259d84b6d923d2769ce260cdab0ad17673ef7388c020b8e8bcd055232a7240fe2fa4fcbeadbc46366aa477
        29f5502dbfee8a623ab8ec6f6020013aeff975f255b597a11eed1335457b9903da42a27a39fdb0edbb11742e4e521c833b7952d3fd28f428eecb
        6f78b99ff0a5eb097793f78f1a70612811766fcbe0f9aa3ca4afd8a364f5584333d8a4cdc096a3762ea6cce70dfa42967f5a7c2dbef688b37885
        fa26220dc800bcb1ae83d35ffca54a6dabba730764d60b1a4a506206efa380d7d1d89069778b082bb92396af4547024797797e01c927c78c9f70
        750ef2002dfe1516baa4f165a3176942d35d9527f4b33505484130cd573f9d4a1f1e6656aff881aab482fb3d6151ab02f76267033f3feb9718fb
        fed05a9b69a8d817a7e4a41efbe3ffeb355d1013778f14d4c30c92a386190fa23b388feddc635b22d8fa4998b65d483cd3b595553092123e144c
        49d91ddc2f7a88f3ef1ad2b0b19636bc3f50f61ea5157c73a1a5b956349b6cdf3ff50ec9ef7cbc1137b27d7839276a3ed4e778c505206669686e
        f038b5808117fedf60ef3598e8ed1db1e5ad64f04af38e60e82fe04bc75594fd9fcd8bb79237adb9c9ffd3dc2c907345f874aec7055576a32263
        486120ff62ad690a988919e941d33ed93706f6984032e205084cc46585b5aef035c22ddbb3b0ba04e83f80c1b06b4975f00207b357550d244051
        89412ea6a83ad56c4873f499fdbdc761aa72".replace("\n", "").replace(" ", "")).unwrap();

        let ss = hex::decode("2fae7214767890c4703fad953f5e3f91303111498caa135d77cde634151e71b5").unwrap();

        let ss2 = decapsulate(ct.try_into().unwrap(), sk.try_into().unwrap());

        assert_eq!(ss, ss2);
    }
}
