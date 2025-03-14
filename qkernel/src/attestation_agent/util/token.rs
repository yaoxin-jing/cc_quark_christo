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

use crate::{qlib::linux::time::Timespec, MonotonicNow};
use alloc::string::String;
use crate::qlib::common::Result;
use jwt_compact::prelude::Claims;

#[derive(Default, Clone, Debug)]
pub struct Token {
    pub inhalt: String,
    exp: Option<Timespec>,
    not_before: Option<Timespec>
}

impl Token {
    pub(crate) fn new(token: String) -> Result<Self> {
        //TODO: decode to str - JWT format
        //Extract time stamps
        let claim_enc = token.split(".").nth(1)
            .expect("AA - JWT expected format: header.claim.signature");
        let claim = base64::decode_config(claim_enc, base64::URL_SAFE_NO_PAD)
            .expect("AA - Failed to decode JWToken");
        debug!("VM: Token - claim_decoded: {:?}", claim);
        let jwt = serde_json::from_slice::<Claims<serde_json::Value>>(&claim.as_slice())
            .expect("AA - Failed to deserialize JWT token");
        debug!("VM: Token - claim_JWT: {:?}", jwt);
        //
        //TODO! - extractact time validity
        //
       // let _exp: Timespec = Timespec {
       //     tv_sec: jwt.exp,
       //     tv_nsec: 0i64,
       // };
       // let iat: Timespec = Timespec {
       //     tv_sec: jwt.iat,
       //     tv_nsec: 0i64,
       // };
        Ok(Self{
            inhalt: token,
            exp: None,
            not_before: None,
        })
    }

    pub(crate) fn is_valid(&self) -> bool {
        let now = MonotonicNow();
        if self.inhalt.is_empty() || self.exp.map_or_else(|| false,
            |e| e.tv_sec >= now ) {
            debug!("AA - Invalid token");
            return false;
        }
        true
    }
}
