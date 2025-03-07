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

use alloc::{boxed::Box, vec::Vec};

use crate::drivers::tee::attestation::{Challenge, Response};
use crate::qlib::common::Result;

use super::InitDataStatus;

pub trait AttesterT {
    fn get_tee_evidence(&self, challenge: &mut Challenge) -> Result<Response>;

    fn check_init_data(&self, _init_data: Vec<u8>) -> Result<InitDataStatus> {
        Ok(InitDataStatus::Unsupported)
    }

    fn extend_runtime_measurement(&self) -> Result<bool> {
        Ok(false)
    }
}

pub type Attester = Box<dyn AttesterT>;
