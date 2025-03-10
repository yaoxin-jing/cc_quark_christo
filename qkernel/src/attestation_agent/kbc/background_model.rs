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

use aes_gcm::aead::{OsRng, Buffer};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use sha2::Sha384;

use crate::attestation_agent::util::connection::{tls_connection, ConnError, ConnectionClient, HttpReq, HttpSClient, KbsResponce, RespType};
use crate::attestation_agent::util::keys::{TeeKeyPair, TeePubKey};
//use crate::attestation_agent::util::Resource;
use crate::attestation_agent::{AttestationAgent, AttestationAgentT};
use crate::qlib::common::Result;
use crate::attestation_agent::util::token::Token;
use crate::qlib::linux_def::{MemoryDef, SysErr};
use crate::qlib::common::Error;

use super::{KbsClient, KbsClientT};

#[derive(Default)]
pub struct BackgroundCkeck;

impl KbsClientT for KbsClient<BackgroundCkeck> {
    fn kbs_address(&self) -> String {
        self._kbs_address()
    }

   // fn create_connect_client(&mut self) -> HttpSClient {
   //     let httpc = HttpSClient::create_http_client(self.kbs_address(),
   //         super::KBC_KEY_LENGTH, super::KBC_ENC_ALG);
   //     self.conn_client.http_client.replace(httpc.clone());
   //     httpc
   // }

   // fn connect_to_kbs(&mut self, httpc: &HttpSClient, read_rec: &mut [u8],
   //     write_rec: &mut [u8], rng: &mut OsRng) {
   //     let tls_con = tls_connection(&httpc, read_rec, write_rec, rng)
   //         .map_err(|e| {
   //             panic!("VM: AttAgent - Failed to create TLS connection to  KBS:{:?}",e);
   //         })
   //         .unwrap();
   //     self.conn_client.tls_conn.replace(tls_con);
   // }

   // fn update_intern_connect<'a>(&'a mut self,
   //     tls: embedded_tls::blocking::TlsConnection<'a, HttpSClient, embedded_tls::Aes128GcmSha256>,
   //     httpc: HttpSClient) {
   //     self.conn_client.http_client.replace(httpc);
   //     self.conn_client.tls_conn.replace(tls);
   // }

    fn get_token(&self, tee: String, conn_client: &mut ConnectionClient, aa: &AttestationAgent)
        -> Result<(Token, TeeKeyPair/*, Option<HttpSClient>*/)> {
        let resp;
        if let Some(_token) = &self.token {
            if _token.is_valid() {
                return Ok((_token.clone(), self.tee_key.clone().unwrap()/*, None*/));
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
        let (token, tk_pair/*, http_client*/) = resp.unwrap();
       // self.http_client = Some(http_client);
       // let _ = self.update_token(Some(token.clone()), Some(tk_pair.clone()))?;
        Ok((token, tk_pair/*, Some(http_client)*/))
    }

    fn update_token(&mut self, token: Option<Token>, tk_pair: Option<TeeKeyPair>) -> Result<()> {
        if token.is_none() || tk_pair.is_none() {
            Err(Error::SystemErr(SysErr::EINVAL))
        } else {
            self.token = token;
            self.tee_key = tk_pair;
            Ok(())
        }
    }

    fn get_resource(&mut self, _uri: super::ResourceUri) -> Result<Vec<u8>> {
        todo!()
    //    let mut read_record = [0u8; HttpSClient::TLS_RECORD];
    //    let mut write_record = [0u8; HttpSClient::TLS_RECORD];
    //    let mut rng = OsRng;
    //    let http_client: HttpSClient = self.conn_client.http_client.clone().unwrap();
    //   // let tls_conn_res = tls_connection(&http_client, &mut read_record,
    //   //     &mut write_record, &mut rng);
    //   // if tls_conn_res.is_err() {
    //   //     debug!("VM: RCAR handshake failed - not TLS conn.");
    //   //     return Err(crate::qlib::common::Error::IOError(String::from("TlsConn")));
    //   // }
    //   // let mut tls_conn = tls_conn_res.unwrap();
    //    let mut tls_conn = self.conn_client.tls_conn.take().unwrap();
    //    let resource_req = HttpReq::Get(self.request_resource(&_uri, "".to_string()));
    //    let request = match resource_req {
    //        HttpReq::Get(s) => s,
    //        _ => {
    //            panic!("not expected")
    //        },
    //    };
    //    debug!("VM: send resource request:{:?}", request);
    //    let resp_res = HttpSClient::send_request(&mut tls_conn, request);
    //    self.conn_client.tls_conn.replace(tls_conn);
    //    if resp_res.is_err() {
    //        return resp_res;
    //    }
    //    let resp = RespType::Resource(resp_res.unwrap());
    //    let kbs_resp_res = HttpSClient::parse_http_responce(resp);
    //    if kbs_resp_res.is_err() {
    //        let _ = kbs_resp_res.as_ref().map_err(|e| {
    //            return e;
    //        });
    //    }
    //    let kbs_resp: KbsResponce = kbs_resp_res.unwrap();
    //    let resource: kbs_types::Response = kbs_resp.resource.unwrap();
    //    let plaintext: Result<Vec<u8>> = self.decrypt_resource(resource, todo!());
    //    if plaintext.is_err() {
    //        error!("AA - Decrypting resource failed");
    //    }
    //    plaintext
    }

    fn decrypt_payload(&mut self, _packet: super::AnnotationPacket) -> Result<Vec<u8>> {
        todo!("Support for ocrypt is not considert")
    }

    fn update_intern(&mut self, http_client: HttpSClient) {
       // let _ = self.conn_client.http_client.replace(http_client);
    }
}

impl<BackgroundCkeck> KbsClient<BackgroundCkeck> {
    const KBS_RCAR_RETRY: u8 = 1;
    const MAX_RESOURCE_REQUEST_RETRY: u8 = 5;
    const KBS_RCAR_TIMEOUT_SEK: u8 = 1;
    const KBS_HASH: &'static str = "SHA512";

    fn do_rcar_handshake(&self, tee: String, conn_client: &mut ConnectionClient, aa: &AttestationAgent)
        -> Result<(Token, TeeKeyPair/*, HttpSClient*/)> {
        let mut retry: u8 = 0;
        //Is this part of config?
        //let key_length: usize = 2048;
        //let encr_alg: String = "RSA1_5".to_string();
        //let client = HttpSClient::create_http_client(&self.kbs_host_addres,
        //    KbsClient::KBC_KEY_LENGTH, KbsClient::KBC_ENC_ALG);
        //Dummy TEST
        //if client.tee_key.is_some() {
        //    debug!("VM: http client created - TeeKeyPair generated");
        //} else {
        //    panic!("VM: http client - no TeeKeyPair");
        //}
        loop {
            //let mut mclient = conn_client.http_client.clone();
            //if mclient.tee_key.is_some() {
            //    debug!("VM: http client cloned - TeeKeyPair generated");
            //} else {
            //    panic!("VM: http client cloned - no TeeKeyPair");
            //}
            if retry < Self::KBS_RCAR_RETRY {
                let _res = self.rcar_handshake(conn_client/*&mut mclient*/, tee.clone(), aa);
                match _res {
                    Ok((token, tkeyp)) => {
                        return Ok((token, tkeyp/*, mclient*/));
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

    //
    // RCAR handshake - In the end we get a (Token, TeeKeyPair) where the Token certifies the
    // TeeKeyPair, and the http client with the connection to retrive resources.
    fn rcar_handshake(&self, _http_client: &mut ConnectionClient /*HttpSClient*/, tee: String, aa: &AttestationAgent)
        -> Result<(Token, TeeKeyPair)> {
        debug!("VM: Do RCAR handshake");
        //let mut read_record = [0u8; HttpSClient::TLS_RECORD];
        //let mut write_record = [0u8; HttpSClient::TLS_RECORD];
        //let mut rng = OsRng;
        //let bind_client = http_client.clone();
        //let tls_conn_res = tls_connection(&bind_client, &mut read_record,
        //    &mut write_record, &mut rng);
        //if tls_conn_res.is_err() {
        //    debug!("VM: RCAR handshake failed - not TLS conn.");
        //    return Err(ConnError::to_err(ConnError::NoTlsConn));
        //}

        //let mut tls_conn = tls_conn_res.unwrap();
        let mut http_client = _http_client.http_client.clone();
        //let mut tls_conn = self.conn_client.tls_conn.take().unwrap();
        let mut req_type = HttpReq::Post(self.request_challenge());
        let challenge_request = HttpSClient::build_request(tee, self.kbs_version.clone(),
            "".to_string(), &req_type);
        let challenge_req_res = HttpSClient::send_request(&mut _http_client.tls_conn, challenge_request);
        if challenge_req_res.is_err() {
            debug!("VM: RCAR handshake failed - talking to KBS failed.");
           // self.conn_client.tls_conn.replace(tls_conn);
            let _ = challenge_req_res.as_ref().map_err(|e| {
                return Err::<(Token, TeePubKey),_>(e);
            });
        }
        let resp = challenge_req_res.unwrap();
        let resp_type = RespType::Challenge(resp);
        let responce_res = HttpSClient::parse_http_responce(resp_type);
        if responce_res.is_err() {
            //self.conn_client.tls_conn.replace(tls_conn);
            let _ = responce_res.as_ref().map_err(|e| {
                debug!("VM: Response is err:{:?}",e);
                return Err::<(Token, TeePubKey),_>(e);
            });
        }
        let responce: KbsResponce = responce_res.unwrap();
        _http_client.cookie = responce.cookie.clone().unwrap();
        http_client.cookie = _http_client.cookie.clone();
        debug!("VM: Dummy 01");
        debug!("VM: RCAR - cookie:{:?}", http_client.cookie);
        debug!("VM: Dummy 02");

        let pub_tkey: TeePubKey = http_client.tee_key.clone().unwrap().export_tee_pub_key();
        let hushed_data = self.hash_data(pub_tkey.clone(), responce)
            .expect("AA - hash response failed");
        let hw_meas = aa.get_tee_evidence(hushed_data.clone()).unwrap();
        //let mut temp: Vec<u8> = vec![0u8; res.len()]; 
        //temp.copy_from_slice(&res[..]);
        //let hw_meas = String::from_utf8(temp).unwrap();
        req_type = HttpReq::Post(self.request_attestation(http_client.cookie.clone()));
        let att_report = HttpSClient::build_attest_report(pub_tkey,
            hw_meas, &req_type);
        let att_rep_res = HttpSClient::send_request(&mut _http_client.tls_conn, att_report);
        if att_rep_res.is_err() {
            //self.conn_client.tls_conn.replace(tls_conn);
            debug!("VM: RCAR handshake failed - talking to KBS failed.");
            let _ = att_rep_res.as_ref().map_err(|e| {
                return Err::<(Token, TeePubKey),_>(e);
            });
        }
        let res = att_rep_res.unwrap();
        let resp_type = RespType::Attestation(res);
        let att_resp_res = HttpSClient::parse_http_responce(resp_type);
        if att_resp_res.is_err() {
            //self.conn_client.tls_conn.replace(tls_conn);
            debug!("VM: RCAR handshake failed - attestation report parsing.");
            let _ = att_resp_res.as_ref().map_err(|e| {
                return Err::<(Token, TeePubKey),_>(e);
            });
        }
        let att_report: KbsResponce = att_resp_res.unwrap();
        let token = Token::new(att_report.token.unwrap())
            .expect("Invalid token");
        //////////////////////////////////////////////
        let _repo = String::from("default");
        let _type = String::from("test");
        let _tag = String::from("dummy");
        let uri = crate::attestation_agent::util::ResourceUri {
            kbs_address: aa.config.kbs_url(),
            repository: _repo,
            r#type: _type,
            tag: _tag,
            query: None};
       // let r = tls_conn.close();
       // if r.is_err() {
       //     panic!("Failed to close TLS connection");
       // }
        let resource_req = HttpReq::Get(self.request_resource(&uri, http_client.cookie.clone()));
        let request = HttpSClient::create_req_head(&resource_req);
        debug!("VM: send resource request:{:?}", request);
        let resp_res = HttpSClient::send_request(&mut _http_client.tls_conn, request);
        if resp_res.is_err() {
            //return resp_res;
            debug!("VM: AA - resource req failed - return:{:?}", resp_res);
            return Ok((token, http_client.tee_key.clone().unwrap()));
        }
        let resp = RespType::Resource(resp_res.unwrap());
        let kbs_resp_res = HttpSClient::parse_http_responce(resp);
        if kbs_resp_res.is_err() {
            let _ = kbs_resp_res.as_ref().map_err(|e| {
                return e;
            });
        }
        let kbs_resp: KbsResponce = kbs_resp_res.unwrap();
        let resource: kbs_types::Response = kbs_resp.resource.unwrap();
        let plaintext: Result<Vec<u8>> = self.decrypt_resource(resource, http_client.tee_key.clone());
        if plaintext.is_err() {
            error!("AA - Decrypting resource failed");
        } else {
            //TEST
            let text = String::from_utf8(plaintext.unwrap())
             .expect("Dummy plaintext from cipher text");
            debug!("VM: AA - Plaintext:{:?}", text);
        }
        //////////////////////////////////////////////
        Ok((token, http_client.tee_key.clone().unwrap()))
    }

    fn hash_data(&self, pub_tkey: TeePubKey, to_hash_data: KbsResponce) -> Result<Vec<u8>> {
        let hashed_data: Result<Vec<u8>>;
        if let Some(hash_code) = &to_hash_data.extra_params {
            //TODO: fixme 
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
        //let mut to_hash: Vec<Vec<u8>> = vec![];
        debug!("VM: Hash runtime - Nonce:{:?}, Nonce-length:{}", nonce, nonce.len());
        let challenge = if let Some(sw_meas) = runtime_measurement {
          //  to_hash.push(sw_meas.into_bytes());
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
        //to_hash.push(nonce.into_bytes());
        //to_hash.push(pub_key.k_mod.into_bytes());
        //to_hash.push(pub_key.k_exp.into_bytes());
        let mut _h: Sha512  = Sha512::new();
        //for block in to_hash {
        //    _h.update(block);
        //}
        _h.update(challenge);
        let _res = _h.finalize();
        //let enc = Base64::encode_string(&res);
        let mut res: Vec<u8> = vec![];
        res.extend_from_slice(&_res);
        Ok(res)
    }

    fn hash_data_sha384(pub_key: TeePubKey, nonce: String,
        runtime_measurement: Option<String>) -> Result<Vec<u8>> {
        use sha2::{Sha384, Digest};
        //let mut to_hash: Vec<Vec<u8>> = vec![];
        debug!("VM: Hash runtime - Nonce:{:?}, Nonce-length:{}", nonce, nonce.len());
        let challenge = if let Some(sw_meas) = runtime_measurement {
          //  to_hash.push(sw_meas.into_bytes());
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
        //to_hash.push(nonce.into_bytes());
        //to_hash.push(pub_key.k_mod.into_bytes());
        //to_hash.push(pub_key.k_exp.into_bytes());
        let mut _h: Sha384  = Sha384::new();
        //for block in to_hash {
        //    _h.update(block);
        //}
        _h.update(challenge);
        let _res = _h.finalize();
        //let enc = Base64::encode_string(&res);
        debug!("VM: Hashed Sha384: {:?} - length:{}", _res, _res.len());
        let mut res: Vec<u8> = vec![];
        res.extend_from_slice(&_res);

        //let res = String::from_utf8_lossy(&res).to_string();
        Ok(res)
    }
}
