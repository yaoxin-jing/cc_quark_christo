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

use crate::qlib::common::Error;
use crate::qlib::common::Result;

use aes_gcm::aead::OsRng;
use alloc::{string::String, vec::Vec};
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TeePubKey {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "n")]
    pub k_mod: String,
    #[serde(rename = "e")]
    pub k_exp: String,
}

#[derive(Clone)]
pub struct TeeKeyPair {
    priv_key: RsaPrivateKey,
    pub pub_key: RsaPublicKey,
    pub key_length: usize,
    pub alg: String
}

impl TeeKeyPair {
    pub fn new(pub_key_length: usize, _alg: String) -> Result<Self> {
        let mut rng = OsRng;
        let pvk = RsaPrivateKey::new(&mut rng, pub_key_length)
            .map_err(|e| { error!("VM: TeeKeyPair - failed to create key:{:?}", e);
                return Error::Common(String::from("TeeRsa-PrivKey generation failed"));
            }).unwrap();
        let pbk = RsaPublicKey::from(&pvk);

        Ok(Self {
            pub_key: pbk,
            priv_key: pvk,
            key_length: pub_key_length,
            alg: _alg
        })
    }

    pub fn export_tee_pub_key(&self) -> TeePubKey {
        let n = base64::encode_config(self.pub_key.n().to_bytes_be(),
            base64::URL_SAFE_NO_PAD);
        let e = base64::encode_config(self.pub_key.e().to_bytes_be(),
            base64::URL_SAFE_NO_PAD);
        TeePubKey{
            kty: String::from("RSA"),
            alg: self.alg.clone(),
            k_mod: n,
            k_exp: e,
        }
    }

    pub fn decrypt(&self, cipher: Vec<u8>) -> Result<Vec<u8>> {
        let res = self.priv_key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &cipher);
        let res = res.expect("RSA_DEC failed");
        Ok(res)
    }
}
