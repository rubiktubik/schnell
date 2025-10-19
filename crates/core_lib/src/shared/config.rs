use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Config {
    pub bundle_identifier: Option<String>,
}

impl Config {
    pub fn new(bundle_identifier: String) -> Self {
        Self {
            bundle_identifier: Some(bundle_identifier),
        }
    }
}
