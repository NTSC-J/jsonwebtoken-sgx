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
    let encrypted =
        sign("hello world", include_bytes!("private_rsa_key.der"), Algorithm::RS256).unwrap();
    let is_valid =
        verify(&encrypted, "hello world", include_bytes!("public_rsa_key.der"), Algorithm::RS256)
            .unwrap();
    assert!(is_valid);
}

pub fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: utc_now_timestamp() + 10000,
    };
    let token =
        encode(&Header::new(Algorithm::RS256), &my_claims, include_bytes!("private_rsa_key.der"))
            .unwrap();
    let token_data = decode::<Claims>(
        &token,
        include_bytes!("public_rsa_key.der"),
        &Validation::new(Algorithm::RS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}
