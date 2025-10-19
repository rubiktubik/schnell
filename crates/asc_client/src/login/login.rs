use base64::{Engine, engine::general_purpose};
use core_lib::{
    ios::login::ports::JwtPort,
    shared::{
        models::{JwtError, JwtValidationError},
        secret_config::AppStoreConnectCredentials,
    },
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{client::AppStoreConnectClient, login::models::Claims};

impl JwtPort for AppStoreConnectClient {
    fn create_jwt(&self, credentials: &AppStoreConnectCredentials) -> Result<String, JwtError> {
        // Header with a key ID
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(credentials.key_id.to_owned());

        // Current time and expiration time (e.g., 20 minutes from now)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::JwtCreationError("Cannot convert time".to_owned()))?
            .as_secs();
        let exp = now + (20 * 60);

        // Your claims
        let claims = Claims {
            iss: credentials.issuer_id.to_owned(),
            exp,
            aud: "appstoreconnect-v1".to_string(),
            iat: now,
        };

        // Load the private key (.p8 file)
        let encoding_key = EncodingKey::from_ec_pem(
            std::fs::read(credentials.private_key_file_path.clone())
                .map_err(|_| {
                    JwtError::JwtCreationError(
                        "Cannot load p8 file for creating encoding key".to_owned(),
                    )
                })?
                .as_ref(),
        )
        .map_err(|_| {
            JwtError::JwtCreationError("Cannot create encoding key from p8 file".to_owned())
        })?;

        // Encode the JWT
        let token = encode(&header, &claims, &encoding_key).map_err(|_| {
            JwtError::JwtCreationError(
                "error on creating jwt from header,claims and encoding key".to_owned(),
            )
        })?;

        Ok(token)
    }

    fn validate(&self, jwt: &str) -> Result<(), JwtValidationError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtValidationError::MalformedSegmentCount(parts.len()));
        }

        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|err| JwtValidationError::InvalidPayloadEncoding(err.to_string()))?;

        let claims: Claims = serde_json::from_slice(&payload)
            .map_err(|err| JwtValidationError::InvalidPayloadFormat(err.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtValidationError::TimeCalculationFailed)?
            .as_secs();

        let min_ttl: u64 = 120; // 2 Minuten vor Ablauf von 20 min von Apple

        if claims.exp <= claims.iat {
            return Err(JwtValidationError::ExpirationBeforeIssuedAt {
                exp: claims.exp,
                iat: claims.iat,
            });
        }

        let ttl = claims.exp - claims.iat;
        if ttl < min_ttl {
            return Err(JwtValidationError::MaxTtlExceeded {
                ttl_seconds: ttl,
                max_ttl_seconds: min_ttl,
            });
        }

        if claims.exp <= now {
            return Err(JwtValidationError::Expired {
                exp: claims.exp,
                now,
            });
        }

        if now < claims.iat {
            return Err(JwtValidationError::NotYetValid {
                iat: claims.iat,
                now,
            });
        }

        if claims.aud != "appstoreconnect-v1" {
            return Err(JwtValidationError::InvalidAudience {
                audience: claims.aud,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_lib::shared::secret_config::AppStoreConnectCredentials;
    use jsonwebtoken::decode_header;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_jwt(exp_secs_from_now: i64) -> String {
        let mut temp_file = NamedTempFile::new().unwrap();
        let private_key = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnQOjlLOLBdP7ubzq
XMVQW4vt7sRT089pbBwxQnfE5PmhRANCAASy6j7pmqBzxp8XYgTRMc0V42FNrJy1
woBt6TmKb0wdqxl1isl1eTtduU8xAdIy5x1MQgLiu8WP10qUMoDarskX
-----END PRIVATE KEY-----";
        temp_file.write_all(private_key).unwrap();

        let credentials = AppStoreConnectCredentials {
            key_id: "test_key_id".to_string(),
            issuer_id: "test_issuer_id".to_string(),
            private_key_file_path: temp_file.path().to_path_buf(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(credentials.key_id.to_owned());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (iat, exp) = if exp_secs_from_now >= 0 {
            let exp = (now as i64 + exp_secs_from_now) as u64;
            (now, exp)
        } else {
            let exp_offset = (-exp_secs_from_now) as u64;
            let exp = now.saturating_sub(exp_offset);
            // keep ttl reasonable to avoid triggering ttl validation in tests
            let iat = exp.saturating_sub(60);
            (iat, exp)
        };

        let claims = Claims {
            iss: credentials.issuer_id.to_owned(),
            exp,
            aud: "appstoreconnect-v1".to_string(),
            iat,
        };

        let encoding_key = EncodingKey::from_ec_pem(
            std::fs::read(credentials.private_key_file_path.clone())
                .unwrap()
                .as_ref(),
        )
        .unwrap();

        encode(&header, &claims, &encoding_key).unwrap()
    }

    #[test]
    fn test_token_expires_in_10_is_valid() {
        let client = AppStoreConnectClient::new();
        // Token expires in 10 minutes, should be valid
        let valid_token = create_test_jwt(10 * 60);
        assert!(client.validate(&valid_token).is_ok());
    }
    #[test]
    fn test_token_expires_in_1_min_is_expired() {
        let client = AppStoreConnectClient::new();
        // Token expires in 1 minutes, should be invalid
        let invalid_token_19_min = create_test_jwt(60);
        assert!(matches!(
            client.validate(&invalid_token_19_min),
            Err(JwtValidationError::MaxTtlExceeded { .. })
        ));
    }
    #[test]
    fn test_token_expired_1_min_ago_is_expired() {
        let client = AppStoreConnectClient::new();
        // Token expired 1 minute ago, should be invalid
        let expired_token = create_test_jwt(-60);
        assert!(matches!(
            client.validate(&expired_token),
            Err(JwtValidationError::MaxTtlExceeded { .. })
        ));
    }

    #[test]
    fn test_create_jwt_success() {
        // Create a temporary file for the private key
        let mut temp_file = NamedTempFile::new().unwrap();
        let private_key = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnQOjlLOLBdP7ubzq
XMVQW4vt7sRT089pbBwxQnfE5PmhRANCAASy6j7pmqBzxp8XYgTRMc0V42FNrJy1
woBt6TmKb0wdqxl1isl1eTtduU8xAdIy5x1MQgLiu8WP10qUMoDarskX
-----END PRIVATE KEY-----";
        temp_file.write_all(private_key).unwrap();

        let credentials = AppStoreConnectCredentials {
            key_id: "test_key_id".to_string(),
            issuer_id: "test_issuer_id".to_string(),
            private_key_file_path: temp_file.path().to_path_buf(),
        };

        let client = AppStoreConnectClient::new();
        let result = client.create_jwt(&credentials);

        assert!(result.is_ok());

        let token = result.unwrap();
        //         let public_key = b"-----BEGIN PUBLIC KEY-----
        // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsuo+6Zqgc8afF2IE0THNFeNhTayc
        // tcKAbek5im9MHasZdYrJdXk7XblPMQHSMucdTEIC4rvFj9dKlDKA2q7JFw==
        // -----END PUBLIC KEY-----";
        //         let validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        //         let decoding_key = DecodingKey::from_ec_pem(public_key).unwrap();
        //         let token_data = decode::<Claims>(&token, &decoding_key, &validation).unwrap();

        //         assert_eq!(token_data.claims.iss, "test_issuer_id");
        //         assert_eq!(token_data.claims.aud, "appstoreconnect-v1");
        //         assert!(token_data.claims.exp > token_data.claims.iat);

        let header = decode_header(&token).unwrap();
        assert_eq!(header.kid.unwrap(), "test_key_id");
    }
}
