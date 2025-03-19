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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::attestation_agent::util::connection::{ConnectionClient,
    HttpReq, KbsResponse, RespType};
use crate::attestation_agent::util::crypto::TeePubKey;
use crate::attestation_agent::{AttestationAgent, AttestationAgentT};
use crate::qlib::common::Result;
use crate::attestation_agent::util::token::Token;
use crate::qlib::linux_def::SysErr;
use crate::qlib::common::Error;

use super::{KbsClient, KbsClientT};

#[derive(Default)]
pub struct BackgroundCkeck;

impl KbsClientT for KbsClient<BackgroundCkeck> {
    fn kbs_address(&self) -> String {
        self._kbs_address()
    }

    fn get_token(&self, tee: String, conn_client: &mut ConnectionClient, aa: &AttestationAgent)
        -> Result<Token> {
        let resp;
        if let Some(_token) = &self.token {
            if _token.is_valid() {
                return Ok(_token.clone());
            } else {
                resp = self.do_rcar_handshake(tee, conn_client, aa);
            }
        } else {
            resp = self.do_rcar_handshake(tee, conn_client, aa);
        }

        if resp.is_err() {
            error!("VM: KBC - failed to get (token, tee_key, cookie) from KBS");
            let _ = resp.as_ref().map_err(|e| {
                return e;
            });
        } else {
            info!("VM: KBC - got (token, tee_key, cookie) from KBS");
        }
        let token = resp.unwrap();
        Ok(token)
    }

    fn update_token(&mut self, token: Option<Token>) -> Result<()> {
        if token.is_none() {
            Err(Error::SystemErr(SysErr::EINVAL))
        } else {
            self.token = token;
            Ok(())
        }
    }

    fn get_resource(&mut self, conn_client: &mut ConnectionClient, uri: super::ResourceUri)
        -> Result<Vec<u8>> {
        let resource_req = HttpReq::Get(self.request_resource(&uri, conn_client.cookie.clone()));
        let request = ConnectionClient::create_req_head(&resource_req);
        debug!("VM: send resource request:{:?}", request);
        let resp_res = conn_client.send_request(request);
        if resp_res.is_err() {
            debug!("VM: AA - resource req failed - return:{:?}", resp_res);
            return Err(Error::Common("Failed request".to_string()));
        }
        let resp = RespType::Resource(resp_res.unwrap());
        let kbs_resp_res = ConnectionClient::parse_http_response(resp);
        if kbs_resp_res.is_err() {
            let _ = kbs_resp_res.as_ref().map_err(|e| {
                return e;
            });
        }
        let kbs_resp: KbsResponse = kbs_resp_res.unwrap();
        let resource: kbs_types::Response = kbs_resp.resource.unwrap();
        let plaintext: Result<Vec<u8>> =
            self.decrypt_resource(resource, self.tee_key.clone());
        if plaintext.is_err() {
            error!("AA - Decrypting resource failed");
            return Err(Error::Common("Failed decrypt-op".to_string()));
        } else {
            let text = String::from_utf8(plaintext.clone().unwrap())
             .expect("Dummy plaintext from cipher text");
            debug!("VM: AA - Plaintext:{:?}", text);
        }
        plaintext
    }
}

impl<BackgroundCkeck> KbsClient<BackgroundCkeck> {
    const KBS_RCAR_RETRY: u8 = 1;
    const MAX_RESOURCE_REQUEST_RETRY: u8 = 5;
    const KBS_RCAR_TIMEOUT_SEK: u8 = 1;
    const KBS_HASH: &'static str = "SHA512";

    fn do_rcar_handshake(&self, tee: String, conn_client: &mut ConnectionClient,
        aa: &AttestationAgent) -> Result<Token> {
        let mut retry: u8 = 0;
        loop {
            if retry < Self::KBS_RCAR_RETRY {
                let _res = self.rcar_handshake(conn_client, tee.clone(), aa);
                match _res {
                    Ok(token) => {
                        return Ok(token);
                    },
                    Err(e) => {
                        match e {
                            Error::IOError(s) => {
                                if s.contains("TlsSockRead") || s.contains("TlsSockSend")
                                || s.contains("TlsConn"){
                                    debug!("VM: Socket operation: {:?} failed - will retry", s);
                                    retry +=1;
                                    continue;
                                }
                                debug!("VM: failed by: {:?}", s);
                                return Err(Error::IOError(s));
                            },
                            _ => {
                                return Err(e);
                            }
                        }
                    }
                }
            } else {
                return Err(Error::Timeout)
            }
        }
    }

    // RCAR handshake - In the end we get a (Token) where the Token
    // certifies the TeeKeyPair of the KBC.
    fn rcar_handshake(&self, http_client: &mut ConnectionClient, tee: String,
        aa: &AttestationAgent) -> Result<Token> {
        debug!("VM: Do RCAR handshake");
        let tee_kp = self.tee_key.clone()
                .expect("KBC key for TEE");
        let pub_tkey: TeePubKey = tee_kp.export_tee_pub_key();
        let mut req_type = HttpReq::Post(self.request_challenge());
        let challenge_request = ConnectionClient::build_request(tee, self.kbs_version.clone(),
            "".to_string(), &req_type);
        let challenge_req_res = http_client.send_request(challenge_request);
        if challenge_req_res.is_err() {
            debug!("VM: RCAR handshake failed - talking to KBS failed.");
            let _ = challenge_req_res.as_ref().map_err(|e| {
                return Err::<Token,_>(e);
            });
        }
        let resp = challenge_req_res.unwrap();
        let resp_type = RespType::Challenge(resp);
        let response_res = ConnectionClient::parse_http_response(resp_type);
        if response_res.is_err() {
            let _ = response_res.as_ref().map_err(|e| {
                debug!("VM: Response is err:{:?}",e);
                return Err::<Token,_>(e);
            });
        }
        let response: KbsResponse = response_res.unwrap();
        http_client.cookie = response.cookie.clone().unwrap();
        debug!("VM: RCAR - cookie:{:?}", http_client.cookie);

        let hushed_data = self.hash_data(pub_tkey.clone(), response)
            .expect("AA - hash response failed");
        let hw_meas = aa.get_tee_evidence(hushed_data.clone()).unwrap();
        req_type = HttpReq::Post(self.request_attestation(http_client.cookie.clone()));
        let att_report = ConnectionClient::build_attest_report(pub_tkey,
            hw_meas, &req_type);
        let att_rep_res = http_client.send_request(att_report);
        if att_rep_res.is_err() {
            debug!("VM: RCAR handshake failed - talking to KBS failed.");
            let _ = att_rep_res.as_ref().map_err(|e| {
                return Err::<Token,_>(e);
            });
        }
        let res = att_rep_res.unwrap();
        let resp_type = RespType::Attestation(res);
        let att_resp_res = ConnectionClient::parse_http_response(resp_type);
        if att_resp_res.is_err() {
            debug!("VM: RCAR handshake failed - attestation report parsing.");
            let _ = att_resp_res.as_ref().map_err(|e| {
                return Err::<Token,_>(e);
            });
        }
        let att_report: KbsResponse = att_resp_res.unwrap();
        let token = Token::new(att_report.token.unwrap())
            .expect("Invalid token");
        Ok(token)
    }

    fn hash_data(&self, pub_tkey: TeePubKey, to_hash_data: KbsResponse) -> Result<Vec<u8>> {
        let hashed_data: Result<Vec<u8>>;
        if let Some(hash_code) = &to_hash_data.extra_params {
            hashed_data = if hash_code.to_uppercase().contains(Self::KBS_HASH) {
                Self::hash_data_sha512(pub_tkey, to_hash_data.nonce.unwrap(), None)
                } else if !hash_code.to_uppercase().contains(Self::KBS_HASH) {
                    Self::hash_data_sha384(pub_tkey,
                        to_hash_data.nonce.unwrap(), None)
                } else {
                    panic!("VM: KBS requested unsupported hash-code:{:?}", hash_code)
                };
        } else {
            // Default
            hashed_data = Self::hash_data_sha384(pub_tkey,
                to_hash_data.nonce.unwrap(), None);
        }
        hashed_data
    }

    fn hash_data_sha512(pub_key: TeePubKey, nonce: String,
        runtime_measurement: Option<String>) -> Result<Vec<u8>> {
        use sha2::{Sha512, Digest};
        debug!("VM: Hash runtime - Nonce:{:?}, Nonce-length:{}", nonce, nonce.len());
        let challenge = if let Some(sw_meas) = runtime_measurement {
            serde_json::json!({
                "tee-pubkey": pub_key,
                "nonce": nonce,
                "runtime": sw_meas, //Experimental
            })
        } else {
            serde_json::json!({
                "tee-pubkey": pub_key,
                "nonce": nonce,
            })
        };
        let binding = serde_json::to_string(&challenge)
            .unwrap();
        let challenge = binding.as_bytes();
        let mut _h: Sha512  = Sha512::new();
        _h.update(challenge);
        let _res = _h.finalize();
        let mut res: Vec<u8> = vec![];
        res.extend_from_slice(&_res);
        Ok(res)
    }

    fn hash_data_sha384(pub_key: TeePubKey, nonce: String,
        runtime_measurement: Option<String>) -> Result<Vec<u8>> {
        use sha2::{Sha384, Digest};
        debug!("VM: Hash runtime - Nonce:{:?}, Nonce-length:{}", nonce, nonce.len());
        let challenge = if let Some(sw_meas) = runtime_measurement {
            serde_json::json!({
                "tee-pubkey": pub_key,
                "nonce": nonce,
                "runtime": sw_meas, // Not supported yet
            })
        } else {
            serde_json::json!({
                "tee-pubkey": pub_key,
                "nonce": nonce,
            })
        };
        let binding = serde_json::to_string(&challenge)
            .unwrap();
        let challenge = binding.as_bytes();
        let mut _h: Sha384  = Sha384::new();
        _h.update(challenge);
        let _res = _h.finalize();
        let mut res: Vec<u8> = vec![];
        res.extend_from_slice(&_res);
        Ok(res)
    }
}
