use anyotp::{HOTP, TOTP};
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn generate_hotp_token(secret: &str, timestamp: u64) -> String {
    let hotp = HOTP::from_base32(secret).unwrap();
    let hotp_key_uri = hotp.to_key_uri("root", Some("AnyOTP"), 1).unwrap();
    println!("hotp_key_uri {}", hotp_key_uri);
    hotp.generate_token(timestamp / 30).unwrap()
}

fn generate_totp_token(secret: &str, timestamp: u64) -> String {
    let totp = TOTP::from_base32(secret).unwrap();
    let totp_key_uri = totp.to_key_uri("root", Some("AnyOTP")).unwrap();
    println!("totp_key_uri {}", totp_key_uri);
    totp.generate_token(timestamp).unwrap()
}

fn main() {
    let secret = "OA6W5CY6EFGDC5I6";
    let now = SystemTime::now();
    thread::sleep(Duration::from_millis(100));
    let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

    let hotp_token = generate_hotp_token(secret, timestamp);
    let totp_token = generate_totp_token(secret, timestamp);

    println!("hotp_token {:?}", hotp_token);
    println!("totp_token {:?}", totp_token);
}
