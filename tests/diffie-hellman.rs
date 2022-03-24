use diffie_hellman::*;

// two biggest 64bit primes
#[cfg(feature = "big-primes")]
const PRIME_64BIT_1: u64 = 0xFFFF_FFFF_FFFF_FFC5;
#[cfg(feature = "big-primes")]
const PRIME_64BIT_2: u64 = 0xFFFF_FFFF_FFFF_FFAC;
#[cfg(feature = "big-primes")]
const PRIVATE_KEY_64BIT: u64 = 0xFFFF_FFFF_FFFF_FFC3;
#[cfg(feature = "big-primes")]
const PUBLIC_KEY_64BIT: u64 = 0xB851_EB85_1EB8_51C1;


#[test]
#[cfg(feature = "big-primes")]
fn test_public_key_correct_biggest_numbers() {
    assert_eq!(
        public_key(PRIME_64BIT_1, PRIME_64BIT_2, PRIVATE_KEY_64BIT),
        PUBLIC_KEY_64BIT
    );
}


#[test]
#[cfg(feature = "big-primes")]
fn test_secret_key_correct_biggest_numbers() {
    let private_key_b = 0xEFFF_FFFF_FFFF_FFC0;
    let public_key_b = public_key(PRIME_64BIT_1, PRIME_64BIT_2, private_key_b);

    let expected_b = 4_340_425_873_327_658_043;
    assert_eq!(public_key_b, expected_b);

    let expected_key = 12_669_955_479_143_291_250;

    let secret_key = secret(PRIME_64BIT_1, public_key_b, PRIVATE_KEY_64BIT);

    assert_eq!(secret_key, expected_key);

    let secret_key = secret(PRIME_64BIT_1, PUBLIC_KEY_64BIT, private_key_b);

    assert_eq!(secret_key, expected_key);
}


#[test]
#[cfg(feature = "big-primes")]
fn test_changed_secret_key_biggest_numbers() {
    let private_key_a = private_key(PRIME_64BIT_1);
    let public_key_a = public_key(PRIME_64BIT_1, PRIME_64BIT_2, private_key_a);

    let private_key_b = private_key(PRIME_64BIT_1);
    let public_key_b = public_key(PRIME_64BIT_1, PRIME_64BIT_2, private_key_b);

    let alice_shared_secret = secret(PRIME_64BIT_1, public_key_b, private_key_a);
    let bob_shared_secret = secret(PRIME_64BIT_1, public_key_a, private_key_b);

    assert_eq!(alice_shared_secret, bob_shared_secret);
}

#[test]
fn test_changed_secret_key() {
    let p: u64 = 13;
    let g: u64 = 11;

    let private_key_a = private_key(p);
    let private_key_b = private_key(p);

    let public_key_a = public_key(p, g, private_key_a);
    let public_key_b = public_key(p, g, private_key_b);

    // Key exchange
    let alice_shared_secret = secret(p, public_key_b, private_key_a);
    let bob_shared_secret = secret(p, public_key_a, private_key_b);

    assert_eq!(alice_shared_secret, bob_shared_secret);

    println!();
    println!("Alice's shared secret {:?}", alice_shared_secret.clone());
    println!("Bob's shared secret {:?}", bob_shared_secret.clone());

    println!();
    println!("Done.")
}



