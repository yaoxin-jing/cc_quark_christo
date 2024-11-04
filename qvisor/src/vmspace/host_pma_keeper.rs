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

use alloc::collections::BTreeSet;
use hashbrown::HashMap;
use spin::Mutex;
use std::collections::VecDeque;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileExt;

use crate::qlib::kernel::arch::tee::is_hw_tee;

use super::super::heap_alloc::ENABLE_HUGEPAGE;
use super::super::memmgr::*;
use super::super::qlib::common::*;
use super::super::qlib::linux_def::*;
use super::super::qlib::mem::areaset::*;
use super::super::qlib::range::*;

#[derive(Clone, Default)]
pub struct HostSegment {}

impl AreaValue for HostSegment {
    fn Merge(&self, _r1: &Range, _r2: &Range, _vma2: &HostSegment) -> Option<HostSegment> {
        return Some(HostSegment {});
    }

    fn Split(&self, _r: &Range, _split: u64) -> (HostSegment, HostSegment) {
        return (HostSegment {}, HostSegment {});
    }
}

pub struct HostPMAKeeper {
    pub ranges: Mutex<AreaSet<HostSegment>>,
    pub hugePages: Mutex<VecDeque<u64>>,
    pub allocPages: Mutex<BTreeSet<u64>>,
    //NOTE: We need this only for Realm
    //  We could make this an Option, but will
    //  require to put PMA_KEERP befind a mutex
    #[cfg(target_arch = "aarch64")]
    file_on_range: Mutex<HashMap<(u64, u64), (std::fs::File, u64)>>,
}

impl HostPMAKeeper {
    pub fn New() -> Self {
        return Self {
            ranges: Mutex::new(AreaSet::New(0, 0)),
            hugePages: Mutex::new(VecDeque::with_capacity(1000)),
            allocPages: Mutex::new(BTreeSet::new()),
            #[cfg(target_arch = "aarch64")]
            file_on_range: Mutex::new(HashMap::new()),
        };
    }

    pub fn FreeHugePage(&self, addr: u64) {
        self.hugePages.lock().push_front(addr);
        self.allocPages.lock().remove(&addr);
    }

    pub fn AllocHugePage(&self) -> Option<u64> {
        let ret = self.hugePages.lock().pop_back();
        match ret {
            None => return None,
            Some(addr) => {
                self.allocPages.lock().insert(addr);
                return Some(addr);
            }
        }
    }

    pub fn DontNeed(&self) -> Result<()> {
        let alloced = self.allocPages.lock();
        for page in alloced.iter() {
            let ret = unsafe {
                libc::madvise(
                    (*page) as _,
                    MemoryDef::PAGE_SIZE_2M as _,
                    libc::MADV_DONTNEED,
                )
            };

            if ret == -1 {
                info!(
                    "DontNeed get error, address is {:x} errno is {}",
                    *page,
                    errno::errno().0
                );
                //return Err(Error::SysError(-errno::errno().0));
            }
        }

        return Ok(());
    }

    pub fn Init(&self, start: u64, len: u64) {
        self.ranges.lock().Reset(start, len);
    }

    pub fn InitHugePages(&self) {
        let hugeLen = (self.ranges.lock().range.Len() / MemoryDef::ONE_GB - 2) * MemoryDef::ONE_GB;
        error!("InitHugePages - Len is {:x}G", self.ranges.lock().range.Len() / MemoryDef::ONE_GB - 2);
        let hugePageStart = self
            .RangeAllocate(hugeLen, MemoryDef::PAGE_SIZE_2M)
            .unwrap();
        let mut addr = hugePageStart;
        while addr < hugePageStart + hugeLen {
            self.FreeHugePage(addr);
            addr += MemoryDef::PAGE_SIZE_2M;
        }
    }

    fn Map(&self, mo: &mut MapOption, r: &Range) -> Result<u64> {
        match mo.MMap() {
            Err(e) => {
                self.RemoveSeg(r);
                return Err(e);
            }
            Ok(addr) => {
                if addr != r.Start() {
                    panic!(
                        "AreaSet <HostSegment>:: memmap fail to alloc fix address at {:x}",
                        r.Start()
                    );
                }

                return Ok(r.Start());
            }
        }
    }

    pub fn MapHugePage(&self) -> Result<u64> {
        let mut mo = &mut MapOption::New();
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let len = MemoryDef::PAGE_SIZE_2M;
        mo = mo.MapAnan().Proto(prot).Len(len);
        if ENABLE_HUGEPAGE {
            mo.MapHugeTLB();
        }

        let start = self.Allocate(len, MemoryDef::PAGE_SIZE_2M)?;
        mo.Addr(start);
        return self.Map(&mut mo, &Range::New(start, len));
    }

    pub fn MapAnon(&self, len: u64, prot: i32) -> Result<u64> {
        let mut mo = &mut MapOption::New();
        mo = mo.MapAnan().Proto(prot).Len(len);
        mo.MapShare();

        let start = self.Allocate(len, MemoryDef::PAGE_SIZE)?;
        mo.Addr(start);
        return self.Map(&mut mo, &Range::New(start, len));
    }

    fn __map_file_directly(&self, mapping_range: Range, prot: i32, fd: i32, offset: u64)
        -> Result<u64> {
        let mut mo = &mut MapOption::New();
        mo = mo
            .Proto(prot)
            .FileOffset(offset)
            .FileId(fd)
            .Len(mapping_range.Len())
            .Addr(mapping_range.Start())
            .MapFixed()
            .MapShare();

        let ret = self.Map(&mut mo, &mapping_range)?;
        Ok(ret)
    }

    fn __map_file_buffered(&self, mapping_range: Range, _prot: i32, fd: i32, offset: u64)
        -> Result<u64> {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut rf_slice = unsafe {
            std::slice::from_raw_parts_mut(mapping_range.Start() as *mut u8,
                mapping_range.Len() as usize)
        };
        let actual_read = file.read(&mut rf_slice);
        if actual_read.is_ok() {
            debug!("VMM: Map file - Read from file: bytes{:#0x}", actual_read.unwrap());
        } else {
            debug!("VMM: Map File - read failed.");
        }
        debug!("VMM: Map file with FD:{}, len:{:#0x}B, host mapped:{:#0x}",
            fd, mapping_range.Len(), mapping_range.Start());
        self.file_on_range.lock().insert((mapping_range.Start(), mapping_range.Len()),
            (file, offset));
        Ok(mapping_range.Start())
    }

    pub fn MapFile(&self, length: u64, prot: i32, fd: i32, offset: u64) -> Result<u64> {
        debug!("VMM: Map file with FD:{}, len:{:#0x} Bytes, offset:{:#0x}, PROT_flags:{:#0x}",
            fd, length, offset, prot);
        let start_addr = self.Allocate(length, MemoryDef::PMD_SIZE)?;
        let mapping_range = Range {start: start_addr, len: length};
        #[cfg(target_arch = "aarch64")]
        if is_hw_tee() {
            let r = self.__map_file_buffered(mapping_range, prot, fd, offset);
            return r;
        }

        self.__map_file_directly(mapping_range, prot, fd, offset)
    }

    fn RangeAllocate(&self, len: u64, alignment: u64) -> Result<u64> {
        let mut ranges = self.ranges.lock();
        let start = ranges.FindAvailable(len, alignment)?;

        let r = Range::New(start, len);
        let gap = ranges.FindGap(start);
        let seg = ranges.Insert(&gap, &r, HostSegment {});
        assert!(seg.Ok(), "AreaSet <HostSegment>:: insert fail");

        return Ok(start);
    }

    fn Allocate(&self, len: u64, alignment: u64) -> Result<u64> {
        assert!(len == MemoryDef::PAGE_SIZE_2M);
        assert!(alignment == MemoryDef::PAGE_SIZE_2M);
        let addr = match self.AllocHugePage() {
            None => {
                error!("AllocHugePage fail...");
                panic!("AllocHugePage fail...");
            }
            Some(addr) => addr,
        };
        assert!(addr & (MemoryDef::PAGE_SIZE_2M - 1) == 0);
        return Ok(addr);
    }

    pub fn RemoveSeg(&self, r: &Range) {
        if r.Len() <= MemoryDef::PAGE_SIZE_2M {
            self.FreeHugePage(r.Start());
            return;
        }

        let mut ranges = self.ranges.lock();
        let (seg, _gap) = ranges.Find(r.Start());

        if !seg.Ok() || !seg.Range().IsSupersetOf(r) {
            panic!(
                "AreaSet <HostSegment>::Unmap invalid, remove range {:?} from range {:?}",
                r,
                seg.Range()
            );
        }

        let seg = ranges.Isolate(&seg, r);

        ranges.Remove(&seg);
    }

    pub fn Unmap(&self, r: &Range) -> Result<()> {
        assert!(r.Start() % MemoryDef::PAGE_SIZE_2M == 0);
        assert!(r.Len() == MemoryDef::PAGE_SIZE_2M);

        self.FreeHugePage(r.Start());

        debug!("VMM: Unmap file len:{:#0x}B, guest mapped:{:#0x}", r.Len(), r.Start());
        #[cfg(target_arch = "aarch64")] {
            if is_hw_tee() {
                let f = self.file_on_range.lock().remove(&(r.Start(), r.Len()));
                if f.is_some() {
                    debug!("VMM: unmap file from:{:#0x} - length:{:#0x}.", r.Start(), r.Len());
                } else {
                    debug!("VMM: no file found at:{:#0x}", r.Start());
                }
            }
        }

        let res = MapOption::MUnmap(r.Start(), r.Len());
        return res;
    }

    #[cfg(target_arch = "aarch64")]
    pub fn write_back(&self, data_heap_address: u64, data_size: usize) -> u64 {
        let ranges_array = unsafe {
            std::slice::from_raw_parts(data_heap_address as *const Range, data_size)
        };
        debug!("VMM: Write back changes to the file");
        let range_start = ranges_array[0].Start();
        let rs_size = ranges_array[0].Len();
        for (_key, _file) in self.file_on_range.lock().iter() {
            if _key.0 <= range_start && (_key.0 + _key.1 > range_start) {
                debug!("VMM: Found file buffered at:{:#0x} - length:{:#0x}", range_start, rs_size);
                let  file_offset = _file.1;
                let mut write_back_range: Range =
                    Range { start: range_start, len: rs_size };
                for i in 1..data_size {
                    if write_back_range.Start() + write_back_range.Len() + 1
                        == ranges_array[i].Start() {
                        write_back_range.len += ranges_array[i].Len();
                    } else {
                        Self::__write_back(&_file.0, &write_back_range, file_offset, _key.0);
                        write_back_range.start = ranges_array[i].Start();
                        write_back_range.len = ranges_array[i].Len();
                    }
                }
                Self::__write_back(&_file.0, &write_back_range, file_offset, _key.0);
                break;
            }
        }
        0
    }

    #[cfg(target_arch = "aarch64")]
    fn __write_back(file: &std::fs::File, range: &Range, file_offset: u64, mapping_start: u64) {
        let buff = unsafe {
            std::slice::from_raw_parts(range.Start() as *const u8, range.Len() as usize)
        };
        let _offset = file_offset + (range.Start() - mapping_start);
        let written = file.write_at(buff, _offset);
        if written.is_ok() {
            debug!("VMM: write back to file offset:{:#0x} - at:{:#0x}\
                - len:{:#0x} B - written:{:#0x} B", _offset, range.Start(),
                range.Len(), written.unwrap());
        } else {
            panic!("VMM: write back failed - could not write to file.");
        }
    }
}

impl AreaSet<HostSegment> {
    fn FindAvailable(&mut self, len: u64, alignment: u64) -> Result<u64> {
        let mut gap = self.FirstGap();

        while gap.Ok() {
            let gr = gap.Range();
            if gr.Len() >= len {
                let offset = gr.Start() % alignment;
                if offset != 0 {
                    if gr.Len() >= len + alignment - offset {
                        return Ok(gr.Start() + alignment - offset);
                    }
                } else {
                    return Ok(gr.Start());
                }
            }

            gap = gap.NextGap();
        }

        return Err(Error::SysError(SysErr::ENOMEM));
    }
}
