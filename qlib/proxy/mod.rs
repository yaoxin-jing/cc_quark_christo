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

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u64)]
pub enum Command {
    Cmd1 = 1 as u64, // cuInit
    Cmd2, // cuDeviceGet
    Cmd3, // cuCtxCreate_v2
    Cmd4, // cuMemAlloc_v2
    Cmd5, // cuMemcpyHtoD_v2
    Cmd6, // cuMemcpyDtoH_v2
    Cmd7, // cuModuleLoad
    Cmd8, // cuModuleGetFunction
    Cmd9, // get CUfunction parameter sizes
    Cmd10, // cuLaunchKernel
    Cmd11, // cuMemFree_v2
    Cmd12, // cuDriverGetVersion
    Cmd13, // cuDeviceGetCount
    Cmd14, // hidden_0_1
    Cmd15, // cuDeviceGetName
    Cmd16, // cuDeviceTotalMem_v2
    Cmd17, // cuDeviceGetAttribute
    Cmd18, // cuDeviceGetUuid
    Cmd19, // cuCtxGetDevice
    Cmd20, // cuCtxSetCurrent
    Cmd21, // cuCtxGetCurrent
    Cmd22, // hidden_0_6
    Cmd23, // hidden_3_2
    Cmd24, // cuDevicePrimaryCtxRetain
    Cmd25, // hidden_3_0
    Cmd26, // hidden_0_5
    Cmd27, // cudaMalloc
    Cmd28, // __cudaRegisterFatBinary
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd1In {
    pub val: u32,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd1Out {
    pub val: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd2In {
    pub val: i32,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd2Out {
    pub val_u32: u32,
    pub val_i32: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd3In {
    pub flags: u32,
    pub dev: i32,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd3Out {
    pub CUresult: u32,
    pub val: u64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd4In {
    pub val: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd4Out {
    pub val_u32: u32,
    pub val_u64: u64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd5In {
    pub devptr: u64,
    pub hostptr: u64,
    pub bytecount: u64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd7In {
    pub ptr: u64,
    pub length: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd9InOut {
    pub func: u64,
    pub ptr: u64,
    pub numParams: u32,
    pub totalParamSize: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd10In {
    pub func: u64,
    pub stream: u64,
    pub params: u64,
    pub extra: u64,
    pub offsets: u64,
    pub numParams: u32,
    pub totalParamSize: u32,
    pub gridDimX: u32,
    pub gridDimY: u32,
    pub gridDimZ: u32,
    pub blockDimX: u32,
    pub blockDimY: u32,
    pub blockDimZ: u32,
    pub sharedMemBytes: u32,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd15In {
    pub buf: u64,
    pub len: u32,
    pub dev: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd17In {
    pub attrib: u32,
    pub dev: i32,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd18In {
    pub val_u64: u64,
    pub val_u32: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd25In {
    pub val_u64: u64,
    pub val_u32: u32,
    pub val_i32: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd26In {
    pub val1_u64: u64,
    pub val2_u64: u64,
    pub val3_u64: u64,
    pub val4_i32: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cmd28In {
    pub val1_u32: u32,
    pub val2_u32: u32,
    pub val3_u64: u64,
    pub val4_u64: u64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct FatbinHeader {
    pub val1_u32: u32,
    pub val2_u16: u16,
    pub val3_u16: u16,
    pub val4_u64: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Cmd28Out {
    pub val: u64,
}