// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//NOTE: Remove and add when commit background_model
pub mod background_model;

use aes_gcm::{aead::{Aead, OsRng}, Aes256Gcm, Key, KeyInit, Nonce};
use alloc::{boxed::Box, string::{String, ToString}, vec::Vec};
use zeroize::Zeroizing;

use crate::qlib::common::Result;

use self::background_model::BackgroundCkeck;

use super::{util::{connection::{ConnectionClient, HttpSClient}, keys::TeeKeyPair, token::Token, AnnotationPacket, ProtectedHeader, ResourceUri}, AttestationAgent};

pub type Kbc = Box<dyn KbsClientT>;

pub enum KbsClientType {
    BckgCheck,
    PssprtCheck,
}

pub trait KbsClientT {
   //fn create_connect_client(&mut self) -> HttpSClient;
   // fn connect_to_kbs(&mut self, httpc: &HttpSClient,
   //     read_rec: &mut [u8], write_rec: &mut [u8], rng: &mut OsRng);
   // fn update_intern_connect<'a>(&'a mut self,
   //     tls: embedded_tls::blocking::TlsConnection<'a, HttpSClient, embedded_tls::Aes128GcmSha256>,
   //     httpc: HttpSClient);
    fn get_token(&self, tee: String, conn_client: &mut ConnectionClient, aa: &AttestationAgent)
        -> Result<(Token, TeeKeyPair/*, Option<HttpSClient>*/)>;
    fn update_token(&mut self, token: Option<Token>,
        tee_key_pair: Option<TeeKeyPair>) -> Result<()>;
    fn get_resource(&mut self, _uri: ResourceUri) -> Result<Vec<u8>>;
    fn decrypt_payload(&mut self, packet: AnnotationPacket) -> Result<Vec<u8>>;
    fn update_intern(&mut self, http_client: HttpSClient);
    fn kbs_address(&self) -> String;
}

#[derive(Default)]
pub struct KbsClient<T> {
    pub validation_type: T,
    pub tee_key: Option<TeeKeyPair>,
    pub token: Option<Token>,
    pub kbs_host_addres: String,
    pub kbs_cert: Option<String>,
    pub kbs_version: String,
    //pub http_client: Option<HttpSClient>,
    //pub conn_client: ConnectionClient<'a>,
}

pub const KBC_KEY_LENGTH: usize = 2048;
//pub const KBC_ENC_ALG: String = String::from("RSA1_5");

impl<T> KbsClient<T> {
    pub fn _kbs_address(&self) -> String {
        self.kbs_host_addres.clone()
    }

    pub fn request_challenge(&self) -> String {
        let host = "Host: ".to_string() + &self.kbs_host_addres.clone();
        let start = "/kbs/v0/auth HTTP/1.1\r\n".to_string() + &host;
        let head = "\r\nConnection: keep-alive\r\n\
            Content-Type: application/json\r\nContent-Length: ";
        let res = start + head;
        res
    }

    pub fn request_attestation(&self, cookie: String) -> String {
        let host = "Host: ".to_string() + &self.kbs_host_addres.clone();
        let start = "/kbs/v0/attest HTTP/1.1\r\n".to_string() + &host;
        let head = format!("\r\nConnection: keep-alive\r\n\
            Content-Type: application/json\r\nCookie: {}\r\nContent-Length: ",
            cookie);
        let rest = start + head.as_str();
        rest
    }

    pub fn request_resource(&self, req_uri: &ResourceUri, cookie: String) -> String {
        let url = self.kbs_host_addres.clone();
        //let mut cookie = "".to_string();
       // if let Some(h) = &self.http_client {
       //     cookie = h.cookie.clone();
       // }
        let req = format!("/kbs/v0/resource/{}/{}/{} HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\n\r\n",
            req_uri.repository.clone(), req_uri.r#type.clone(), req_uri.tag.clone(), url, cookie);
        req
    }

    pub(crate) fn decrypt_resource(&self, resource: kbs_types::Response, tee_key: Option<TeeKeyPair>/*OntlyToTEST: next get it from self */) -> Result<Vec<u8>> {
        let protected: ProtectedHeader = serde_json::from_str(&resource.protected)
            .expect("Failed to deserialize ProtectedHeader");
        if !protected.alg.contains(tee_key.clone().unwrap().alg.as_str()) {
            debug!("VM: AA - unexpected key encryption alg -{:?}",
                protected.alg);
            return Err(crate::qlib::common::Error::Common("Unxpected argument".to_string()));
        }
        let encr_key = base64::decode_config(&resource.encrypted_key, base64::URL_SAFE_NO_PAD)
            .expect("AA - failed to decode encr-key");
        let key = tee_key.clone().unwrap().decrypt(encr_key)
            .expect("AA - Failed to decrypt key");

        let iv = base64::decode_config(&resource.iv,  base64::URL_SAFE_NO_PAD)
            .expect("AA - Failed to decode Initialization Vector");
        let cipher = base64::decode_config(&resource.ciphertext, base64::URL_SAFE_NO_PAD)
            .expect("AA - Failed to decode ciphertext");

        Self::decrypt(key, iv, cipher, protected.enc)
    }

    fn decrypt(key: Vec<u8>, iv: Vec<u8>, cipher: Vec<u8>, alg: String) -> Result<Vec<u8>> {
        if alg == "A256GCM".to_string() {
            let _key = Zeroizing::new(key);
            let dec_k = Key::<Aes256Gcm>::from_slice(_key.as_slice());
            let block_chipher = Aes256Gcm::new(dec_k);
            let iv = Nonce::from_slice(iv.as_slice());
            let res = block_chipher.decrypt(iv, cipher.as_slice());
            if res.is_err() {
                let _ = res.as_ref().map_err(|e| {
                    error!("AA - data decryption failed error: {:?}", e);
                    return Err::<Vec<u8>, _>(crate::qlib::common::Error::Common("Operation failed".to_string()));
                });
            }
            let data = res.unwrap();
            return Ok(data);
        } else {
            return Err(crate::qlib::common::Error::Common(format!("Not supported enc-alg:{}", alg)));
        }
    }
}

pub fn kbc_build(kbs_type: KbsClientType, url: String, cert: Option<String>) -> Kbc {
    match kbs_type {
        KbsClientType::BckgCheck => {
            return Box::new(KbsClient {
                validation_type: BackgroundCkeck,
                kbs_version: String::from("0.1.1"),
                kbs_host_addres: url,
                kbs_cert: cert,
                ..Default::default()
            });
        },
        _ => panic!("not supported")
    }
}
