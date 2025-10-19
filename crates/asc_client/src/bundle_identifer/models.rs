use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct BundleIdAttributes {
    pub identifier: String,
    pub name: String,
    pub platform: String,
    pub seed_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct BundleId {
    pub id: String,
    pub attributes: BundleIdAttributes,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleIdList {
    pub data: Vec<BundleId>,
}

impl Iterator for BundleIdList {
    type Item = BundleId;

    fn next(&mut self) -> Option<Self::Item> {
        self.data.pop()
    }
}

#[derive(Debug)]
pub struct BundleIdResourceId {
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct CreateBundleIdRequest<'a> {
    pub data: CreateBundleIdRequestData<'a>,
}

#[derive(Debug, Serialize)]
pub struct CreateBundleIdRequestData<'a> {
    #[serde(rename = "type")]
    pub type_name: &'a str,
    pub attributes: CreateBundleIdRequestAttributes<'a>,
}

#[derive(Debug, Serialize)]
pub struct CreateBundleIdRequestAttributes<'a> {
    pub identifier: &'a str,
    pub name: &'a str,
    pub platform: &'a str,
}
