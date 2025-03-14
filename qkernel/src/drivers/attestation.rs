// Copyright (c) 2021 Quark Container Authors
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

use alloc::{vec::Vec, string::String};
use lazy_static::lazy_static;
use core::cell::SyncUnsafeCell;
use spin::{Mutex, lazy::Lazy};

use crate::qlib::{common::{Result, Error},
    linux_def::SysErr};

pub type Challenge = Vec<u8>;
pub type Response = String;

pub(self) mod hw_attestation {
    #[derive(Default)]
    pub struct Dummy;
    pub type TeeAttester = Dummy;

    use super::AttestationDriverT;
    impl AttestationDriverT for Dummy {}
}

use self::hw_attestation::TeeAttester;

lazy_static! {
    pub static ref ATTESTATION_DRIVER: Mutex::<&'static mut AttestationDriver<TeeAttester>> = {
        static DRIVER: Lazy<SyncUnsafeCell<AttestationDriver<TeeAttester>>> =
            Lazy::new(lazy_cell_new::<TeeAttester>);
        let _d = unsafe {
            &mut (*DRIVER.get())
        };

        _d.init();

        Mutex::<&mut AttestationDriver::<TeeAttester>>::new(_d)
    };
}

fn lazy_cell_new<T>() -> SyncUnsafeCell<AttestationDriver<T>>
    where T: core::default::Default + AttestationDriverT{
    SyncUnsafeCell::new(AttestationDriver::<T>::default())
}

pub trait AttestationDriverT {
    fn init(&mut self) {}
    fn get_report(&self, _challenge: &Challenge) -> Result<Response>
        { todo!("Trait not implemented") }
    fn valid_challenge(_challenge: &mut Challenge) -> bool
    { todo!("Trait not implemented") }
    //TODO: Other methods
    //  ...
}

//
// Frontend for requests
//
#[derive(Default)]
pub struct AttestationDriver<T> {
    tee_attester: T,
}

impl<T: AttestationDriverT> AttestationDriver<T> {
    fn init(&mut self) {
        self.tee_attester.init();
    }

    pub fn get_report(&self, challenge: &mut Challenge) -> Result<Response> {
        debug!("VM: Cca-AtD - get report with challenge:{:?}", challenge);
        if T::valid_challenge(challenge) {
            debug!("VM: Challege is valid - request report.");
            return self.tee_attester.get_report(challenge);
        }
        error!("VM: challenge was not in valid format.");
        Err(Error::SystemErr(SysErr::EINVAL))
    }
}
