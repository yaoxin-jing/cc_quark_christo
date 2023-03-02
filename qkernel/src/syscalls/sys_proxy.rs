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
            let dataOut = Cmd1Out { val: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd2 => {
            let dataIn: Cmd1In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd2Out { val_u32: 0, val_i32: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd3 => {
            let dataIn: Cmd3In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd3Out { CUresult: 0, val: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd4 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd5 => {
            let mut dataIn: Cmd5In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };

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
            let dataOut = Cmd1Out { val: 0 };

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
        Command::Cmd7 => {
            let mut dataIn: Cmd7In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd3Out { CUresult: 0, val: 0u64 };

            let buffer: Vec<u8> = task.CopyInVec(dataIn.ptr, dataIn.length as usize)?;
            dataIn.ptr = &buffer[0] as *const _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd8 => {
            let mut dataIn: Cmd5In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd3Out { CUresult: 0, val: 0u64 };

            let buffer: Vec<u8> = task.CopyInVec(dataIn.hostptr, dataIn.bytecount as usize)?;
            dataIn.hostptr = &buffer[0] as *const _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd9 => {
            let mut dataIn: Cmd9InOut = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };

            let mut a = [0u32; 32];
            let save = dataIn.ptr;
            dataIn.ptr = &mut a[0] as *mut _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);

            // task.CopyOutSlice(&a, save, 4*dataIn.numParams as usize)?; // THIS ISN'T WORKING! The length has to be 128
            task.CopyOutSlice(&a, save, 128 as usize)?;
            dataIn.ptr = save;
            task.CopyOutObj(&dataIn, addrIn)?;
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd10 => {
            let mut dataIn: Cmd10In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };

            let mut offsetsCopy: [u32; 32] = task.CopyInObj(dataIn.offsets)?;
            offsetsCopy[dataIn.numParams as usize] = dataIn.totalParamSize;

            let mut paramsPtr: Vec<u64> = task.CopyInVec(dataIn.params, dataIn.numParams as usize)?;
            
            let mut paramsVal = vec![0u8; 0];
            for i in 0..dataIn.numParams {
                let sz = (offsetsCopy[(i+1) as usize] - offsetsCopy[i as usize]) as usize;
                let mut val: Vec<u8> = task.CopyInVec(paramsPtr[i as usize], sz)?;
                paramsVal.append(&mut val);
            }

            for i in 0..dataIn.numParams {
                let offset = offsetsCopy[i as usize];
                paramsPtr[i as usize] = &mut paramsVal[offset as usize] as *mut _ as u64;
            }

            dataIn.params = &mut paramsPtr[0] as *mut _ as u64;

            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);

            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd11 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd12 => {
            let dataOut = Cmd2Out { val_u32: 0, val_i32: 0 };
            let ret = HostSpace::Proxy(commandId, 0, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd13 => {
            let dataOut = Cmd2Out { val_u32: 0, val_i32: 0 };
            let ret = HostSpace::Proxy(commandId, 0, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd14 => {
            let dataIn: Cmd3In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd3Out { CUresult: 0, val: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd15 => {
            let mut dataIn: Cmd15In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };

            let buffer: Vec<u8> = task.CopyInVec(dataIn.buf, dataIn.len as usize)?;
            let guestPtr = dataIn.buf;
            dataIn.buf = &buffer[0] as *const _ as u64;
            
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);

            task.CopyOutSlice(&buffer, guestPtr, dataIn.len as usize)?;
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd16 => {
            let dataIn: Cmd2In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd17 => {
            let dataIn: Cmd3In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd2Out { val_u32: 0, val_i32: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd18 => {
            let mut dataIn: Cmd18In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };

            let buffer: Vec<u8> = task.CopyInVec(dataIn.val_u64, 16 as usize)?;
            let guestPtr = dataIn.val_u64;
            dataIn.val_u64 = &buffer[0] as *const _ as u64;
            
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);

            task.CopyOutSlice(&buffer, guestPtr, 16 as usize)?;
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd19 => {
            let dataOut = Cmd2Out { val_u32: 0, val_i32: 0 };
            let ret = HostSpace::Proxy(commandId, 0, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd20 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd21 => {
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, 0, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd22 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd23 => {
            let dataIn: Cmd18In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd24 => {
            let dataIn: Cmd2In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd25 => {
            let dataIn: Cmd25In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd1Out { val: 0 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd26 => {
            let dataIn: Cmd26In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd27 => {
            let dataIn: Cmd4In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd4Out { val_u32: 0, val_u64: 0u64 };
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
        Command::Cmd28 => {
            let mut dataIn: Cmd28In = task.CopyInObj(addrIn)?;
            let dataOut = Cmd28Out { val: 0u64 };

            let fatbinHdr: FatbinHeader = task.CopyInObj(dataIn.val3_u64)?;
            let fatbinSz: u64 = fatbinHdr.val4_u64 + fatbinHdr.val3_u16 as u64;

            let buffer: Vec<u8> = task.CopyInVec(dataIn.val3_u64, fatbinSz as usize)?;
            dataIn.val3_u64 = &buffer[0] as *const _ as u64;
            
            let ret = HostSpace::Proxy(commandId, &dataIn as * const _ as u64, &dataOut as * const _ as u64);
            task.CopyOutObj(&dataOut, addrOut)?;

            if ret < 0 {
                return Err(Error::SysError(-ret as i32));
            }
        }
    }

    return Ok(0)
}