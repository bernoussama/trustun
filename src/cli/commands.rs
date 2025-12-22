use crate::{IpouError, Result};
use std::convert::TryFrom;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn handle_gen_key() -> Result<()> {
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let builder = snow::Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| IpouError::Unknown(e.to_string()))?;
    println!("{}", base64::encode(&keypair.private));
    Ok(())
}

pub fn handle_pub_key() -> Result<()> {
    println!("Enter your base64 encoded private key (32 bytes): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    let private_bytes = base64::decode(input)?;
    if private_bytes.len() != 32 {
        return Err(IpouError::InvalidKeyLength(private_bytes.len()));
    }
    let arr = <[u8; 32]>::try_from(private_bytes.as_slice())
        .map_err(|_| IpouError::InvalidKeyLength(0))?;
    let static_secret = StaticSecret::from(arr);
    let public = PublicKey::from(&static_secret);
    println!("{}", base64::encode(public.as_bytes()));
    Ok(())
}
