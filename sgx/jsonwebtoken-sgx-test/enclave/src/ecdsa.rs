use std::prelude::v1::*;

use chrono::Utc;
use jsonwebtoken::{decode, encode, sign, verify, Algorithm, Header, Validation};

pub fn utc_now_timestamp() -> i64 {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use std::untrusted::time::SystemTimeEx;
    use chrono::naive::NaiveDateTime;
    use chrono::DateTime;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let now = now.as_secs() as i64;

    now
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

pub fn round_trip_sign_verification() {
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let encrypted = sign("hello world", privkey, Algorithm::ES256).unwrap();
    let pubkey = include_bytes!("public_ecdsa_key.pk8");
    let is_valid = verify(&encrypted, "hello world", pubkey, Algorithm::ES256).unwrap();
    assert!(is_valid);
}

pub fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: utc_now_timestamp() + 10000,
    };
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let token = encode(&Header::new(Algorithm::ES256), &my_claims, privkey).unwrap();
    let pubkey = include_bytes!("public_ecdsa_key.pk8");
    let token_data = decode::<Claims>(&token, pubkey, &Validation::new(Algorithm::ES256)).unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}
