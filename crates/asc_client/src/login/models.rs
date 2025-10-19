#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    // The token’s expiration time in Unix epoch time. Tokens that expire more than 20 minutes into the future are not valid except for resources listed in Determine the Appropriate Token Lifetime.
    pub exp: u64,
    // The token’s creation time, in UNIX epoch time, for example, 1528407600
    pub iat: u64,
    // Your issuer ID from the API Keys page in App Store Connect, for example, 57246542-96fe-1a63-e053-0824d011072a
    pub iss: String,
}
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("error creating jwt, reason {0}")]
    CreationError(String),
}
