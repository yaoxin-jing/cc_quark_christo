// Copyright (c) 2021 Quark Container Authors 
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

use crate::qlib::proxy::*;
use crate::qlib::kernel::Kernel::HostSpace;
use super::super::qlib::common::*;
use super::super::syscalls::syscalls::*;
use super::super::task::*;
use alloc::vec::Vec;

// arg0: command id
// arg1: data in address
// arg2: data out address
pub fn SysProxy(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let commandId = args.arg0 as u64;
    let addrIn = args.arg1 as u64;
    let addrOut = args.arg2 as u64;

    let cmd : Command = unsafe { core::mem::transmute(commandId as u64) };
    match cmd {
        Command::Cmd1 => {
            let dataIn: Cmd1In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { CUresult: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd2 => {
            let dataIn: Cmd1In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd2Out { CUresult: 0, dev: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd3 => {
            let dataIn: Cmd3In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd3Out { CUresult: 0, ctx: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd4 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { CUresult: 0, dptr: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd5 => {
            let mut dataIn: Cmd5In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { CUresult: 0 };

            let buffer: Vec<u8> = task.CopyInVec(dataIn.hostptr, dataIn.bytecount as usize)?;
            dataIn.hostptr = &buffer[0] as *const _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd6 => {
            let mut dataIn: Cmd5In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { CUresult: 0 };

            let buffer = vec![0u8; dataIn.bytecount as usize];
            let hostptr = dataIn.hostptr;
            dataIn.hostptr = &buffer[0] as *const _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutSlice(&buffer, hostptr, dataIn.bytecount as usize)?;
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
    }

    return Ok(0)
}