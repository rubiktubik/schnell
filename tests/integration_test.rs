use assert_cmd::prelude::*;
use std::{fs, process::Command};

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnQOjlLOLBdP7ubzq\nXMVQW4vt7sRT089pbBwxQnfE5PmhRANCAASy6j7pmqBzxp8XYgTRMc0V42FNrJy1\nwoBt6TmKb0wdqxl1isl1eTtduU8xAdIy5x1MQgLiu8WP10qUMoDarskX\n-----END PRIVATE KEY-----\n";

#[test]
fn test_login_with_credentials() {
    let mut cmd = Command::cargo_bin("cli").unwrap();
    let home_dir = std::env::temp_dir().join(format!("rutter-test-home-{}", std::process::id()));
    fs::create_dir_all(&home_dir).unwrap();
    let key_path = home_dir.join("test-private-key.p8");
    fs::write(&key_path, TEST_PRIVATE_KEY).unwrap();
    cmd.arg("ios")
        .arg("login")
        .arg("--issuer-id")
        .arg("some-issuer-id")
        .arg("--key-id")
        .arg("some-key-id")
        .arg("--private-key")
        .arg(&key_path);
    cmd.env("HOME", &home_dir);
    cmd.assert().success();
    let _ = fs::remove_dir_all(home_dir);
}
