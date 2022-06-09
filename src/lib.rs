use std::fmt;

use base64::decode;
use hmac::{Hmac, Mac};
use itertools::Itertools;
use rand::{distributions::Alphanumeric, Rng};
use reqwest;
use reqwest::header;
use rsa::{PaddingScheme, pkcs1::FromRsaPrivateKey, RsaPrivateKey};
use serde_json::{from_str, json, to_string, Value};
use sha2::{Digest, Sha256};

use crate::hwid::get_id;

mod hwid;

type HmacSha256 = Hmac<Sha256>;

pub struct AuthClient<'r> {
    aid: &'r str,
    api_key: &'r str,
    client_secret: &'r str,
    rsa_key: Option<&'r str>,
    pub username: Option<&'r str>,
    pub password: Option<&'r str>,
    contact: Option<&'r str>,
    key: Option<&'r str>,
}

pub struct AuthResponse {
    pub license_type: Option<String>,
    pub license_expiration: Option<String>,
    pub variables: Value,
}

#[derive(Debug)]
pub enum ErrorType {
    InvalidHWID,
    InvalidCredentials,
    ExpiredLicense,
    InvalidHash,
    Other(String),
}

#[derive(Debug)]
pub struct AuthError {
    pub error_type: ErrorType,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.error_type)
    }
}

impl AuthClient<'_> {
    pub fn authenticate(self) -> Result<AuthResponse, AuthError> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let nonce = nonce_gen();

        let payload = json!(
        {
            "username": self.username,
            "password": self.password,
            "hwid": get_id(),
            "aid": self.aid,
            "key": self.api_key,
            "nonce": nonce,
            "hash": get_hash()
        });

        let signature = compute_hmac(self.client_secret, &to_string(&payload).unwrap());

        let mut headers = header::HeaderMap::new();
        let _ = headers
            .entry("x-vege-signature")
            .or_insert(header::HeaderValue::from_str(signature.as_str()).unwrap());

        let resp = client
            .post("https://auth.vegetables.inc/api/v4/authenticate")
            .headers(headers)
            .json(&payload)
            .send()
            .unwrap();

        let resp_signature = resp
            .headers()
            .get("x-vege-signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp_text = resp.text().unwrap();
        let data: Value = from_str(resp_text.as_str()).unwrap();

        if data["success"].as_bool().unwrap() && data["nonce"].as_str().unwrap().to_string() == nonce
        {
            if compute_hmac(&self.client_secret, &resp_text) == resp_signature {
                if !data["licenseInfo"]["expired"].as_bool().unwrap() {
                    let server_variables = data["variables"].clone();
                    let mut decoded_variables = json!({});


                    match self.rsa_key {
                        Some(key) => {
                            let private_key = RsaPrivateKey::from_pkcs1_pem(key).unwrap();

                            for (key, value) in server_variables.as_object().unwrap() {
                                decoded_variables[key] = decode_variable(value.as_str().unwrap(), private_key.clone()).into()
                            }
                        }
                        None => {}
                    }

                    Ok(AuthResponse {
                        license_type: Some(data["licenseInfo"]["license_type"].as_str().unwrap_or("none").to_string()),
                        license_expiration: Some(data["licenseInfo"]["license_type"].as_str().unwrap_or("none").to_string()),
                        variables: decoded_variables,
                    })
                } else {
                    Err(AuthError { error_type: ErrorType::ExpiredLicense })
                }
            } else {
                Err(AuthError { error_type: ErrorType::Other("Invalid HMAC".to_string()) })
            }
        } else {
            if data["errorDetails"]["type"] == "credentials" {
                Err(AuthError { error_type: ErrorType::InvalidCredentials })
            } else if data["errorDetails"]["type"] == "hwid" {
                Err(AuthError { error_type: ErrorType::InvalidHWID })
            } else if data["errorDetails"]["type"] == "hash" {
                Err(AuthError { error_type: ErrorType::InvalidHash })
            } else {
                let e = data["errorDetails"]["type"].as_str().unwrap().to_string();
                Err(AuthError { error_type: ErrorType::Other(e) })
            }
        }
    }

    pub fn register(self) -> String {
        let client = reqwest::blocking::Client::builder()
            .build()
            .unwrap();

        let payload = json!(
        {
            "username": &self.username.unwrap(),
            "password": &self.password.unwrap(),
            "hwid": get_id(),
            "aid": self.aid,
            "key": self.api_key,
            "license": &self.key.unwrap(),
            "contact": &self.contact.unwrap()
        });

        let signature = compute_hmac(self.client_secret, &to_string(&payload).unwrap());

        let mut headers = header::HeaderMap::new();
        let _ = headers
            .entry("x-vege-signature")
            .or_insert(header::HeaderValue::from_str(signature.as_str()).unwrap());

        let resp = client
            .post("https://auth.vegetables.inc/api/v4/register")
            .headers(headers)
            .json(&payload)
            .send()
            .unwrap();

        let resp_signature = resp
            .headers()
            .get("x-vege-signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let resp_text = resp.text().unwrap();
        let data: Value = from_str(resp_text.as_str()).unwrap();

        if data["success"].as_bool().unwrap() {
            if compute_hmac(&self.client_secret, &resp_text) == resp_signature {
                "Registered successfully".to_string()
            } else {
                "Invalid HMAC".to_string()
            }
        } else {
            if data["errorDetails"]["type"] == "invalid license" {
                "Invalid license key".to_string()
            } else {
                data["errorDetails"]["type"].as_str().unwrap().to_string()
            }
        }
    }

    pub fn reset(self) -> String {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        let payload = json!(
        {
            "username": &self.username.unwrap(),
            "password": &self.password.unwrap(),
            "hwid": get_id(),
            "aid": self.aid,
            "key": self.api_key,
            "resetKey": &self.key.unwrap()
        });

        let signature = compute_hmac(self.client_secret, &to_string(&payload).unwrap());

        let mut headers = header::HeaderMap::new();
        let _ = headers
            .entry("x-vege-signature")
            .or_insert(header::HeaderValue::from_str(signature.as_str()).unwrap());

        let resp = client
            .post("https://auth.vegetables.inc/api/v4/reset")
            .headers(headers)
            .json(&payload)
            .send()
            .unwrap();

        let resp_signature = resp
            .headers()
            .get("x-vege-signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp_text = resp.text().unwrap();
        let data: Value = from_str(resp_text.as_str()).unwrap();

        if data["success"].as_bool().unwrap() {
            if compute_hmac(&self.client_secret, &resp_text) == resp_signature {
                "Reset HWID successfully".to_string()
            } else {
                "Invalid HMAC".to_string()
            }
        } else {
            if data["errorDetails"]["type"] == "invalid key" {
                "Invalid reset key".to_string()
            } else if data["errorDetails"]["type"] == "reseting too fast" {
                "You have already reset your hwid in the last 24 hours".to_string()
            } else {
                data["errorDetails"]["type"].as_str().unwrap().to_string()
            }
        }
    }

    pub fn check_version(self, current_version: &str) -> bool {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        let resp = client
            .get(format!("https://auth.vegetables.inc/api/v1/getversion/{}", self.aid))
            .send()
            .unwrap();

        let _version = resp.text().unwrap();

        _version != current_version
    }

    pub fn new(aid: &'static str, api_key: &'static str, client_secret: &'static str, rsa_key: Option<&'static str>) -> Self {
        Self {
            aid,
            api_key,
            client_secret,
            rsa_key,
            username: None,
            password: None,
            contact: None,
            key: None,
        }
    }

    pub fn add_key(mut self, key: &'static str) -> Self {
        self.key = Some(key);
        self
    }

    pub fn add_contact(mut self, contact: &'static str) -> Self {
        self.contact = Some(contact);
        self
    }

    pub fn add_credentials(mut self, username: &'static str, password: &'static str) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }
}

fn compute_hmac(secret: &str, payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .format_with("", |byte, f| f(&format_args!("{:02x}", byte)))
        .to_string()
}

fn get_hash() -> String {
    let path = std::env::args().collect::<Vec<String>>();

    let mut hasher = sha2::Sha256::new();
    let d = std::fs::read(path.get(0).unwrap()).unwrap();
    hasher.update(d);
    let result = hasher.finalize();
    result.iter().format_with("", |byte, f| f(&format_args!("{:02x}", byte))).to_string()
}

fn nonce_gen() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}

fn decode_variable(variable: &str, key: RsaPrivateKey) -> String {
    let decoded = decode(variable).unwrap();
    let b = key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), decoded.as_ref()).unwrap();
    String::from_utf8(b).unwrap()
}

#[cfg(test)]
mod test {
    use crate::AuthClient;

    #[test]
    fn login() {
        let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

        let response = client
            .add_credentials("chanchan", "chanchan's password")
            .authenticate();

        match response {
            Ok(r) => { println!("Successfully logged in, your license type is: {:?}", r.license_type) }
            Err(e) => { println!("An error occurred: {:?}", e.error_type) }
        }
    }

    #[test]
    fn register() {
        let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

        let response = client
            .add_credentials("chanchan", "chanchan's password")
            .add_contact("chanchan@sirchanchan.dev")
            .add_key("LICENSE-dfg-dfhjgdkjfg-eruteuirt")
            .register();

        println!("Auth message: {}", response);
    }

    #[test]
    fn reset_hwid() {
        let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

        let response = client
            .add_credentials("chanchan", "chanchan's password")
            .add_key("RESET-dfg-dfhjgdkjfg-eruteuirt")
            .reset();

        println!("Auth message: {}", response);
    }
}