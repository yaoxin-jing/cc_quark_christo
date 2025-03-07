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

use crate::qlib::common::Result;
use crate::drivers::tee::attestation::{Challenge, Response, ATTESTATION_DRIVER};

use super::AttesterT;

#[derive(Default)]
pub struct CcaAttester();

impl  AttesterT for CcaAttester {
    fn get_tee_evidence(&self, challenge: &mut Challenge) -> Result<Response> {
        ATTESTATION_DRIVER.lock().get_report(challenge)
    }
}

