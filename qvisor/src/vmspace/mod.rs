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

pub mod HostFileMap;
//pub mod TimerMgr;
pub mod host_pma_keeper;
pub mod host_uring;
pub mod hostfdnotifier;
pub mod kernel_io_thread;
pub mod limits;
pub mod random;
pub mod syscall;
pub mod time;
pub mod uringMgr;
pub mod hibernate;

use std::env::temp_dir;
use uuid::Uuid;
use core::sync::atomic;
use core::sync::atomic::AtomicU64;
use lazy_static::lazy_static;
use libc::*;
use serde_json;
use std::fs;
use std::marker::Send;
use std::os::unix::io::IntoRawFd;
use std::slice;
use std::str;
use x86_64::structures::paging::PageTableFlags;
use core::arch::asm;

use crate::qlib::fileinfo::*;
use crate::vmspace::kernel::GlobalIOMgr;
use crate::vmspace::kernel::GlobalRDMASvcCli;

use self::limits::*;
use self::random::*;
use self::syscall::*;
use super::kvm_vcpu::HostPageAllocator;
use super::kvm_vcpu::KVMVcpu;
use super::namespace::MountNs;
use super::qlib::addr::Addr;
use super::qlib::common::{Error, Result};
use super::qlib::control_msg::*;
use super::qlib::kernel::util::cstring::*;
use super::qlib::kernel::SignalProcess;
use super::qlib::linux::membarrier::*;
use super::qlib::linux_def::*;
use super::qlib::pagetable::PageTables;
use super::qlib::perf_tunning::*;
use super::qlib::qmsg::*;
use super::qlib::socket_buf::*;
use super::qlib::task_mgr::*;
use super::qlib::*;
use super::runc::container::mounts::*;
use super::runc::runtime::loader::*;
use super::runc::runtime::signal_handle::*;
use super::runc::specutils::specutils::*;
use super::ucall::usocket::*;
use super::*;
use cuda_driver_sys::*;
use cuda_runtime_sys::*;
use std::ptr;
use std::ffi::{c_void};
// use libloading;

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

lazy_static! {
    static ref UID: AtomicU64 = AtomicU64::new(1);
}

macro_rules! scan {
    ( $string:expr, $sep:expr, $( $x:ty ),+ ) => {{
        let mut iter = $string.split($sep);
        ($(iter.next().and_then(|word| word.parse::<$x>().ok()),)*)
    }}
}

pub fn NewUID() -> u64 {
    return UID.fetch_add(1, atomic::Ordering::SeqCst);
}

pub fn Init() {
    //self::fs::Init();
}

#[derive(Clone, Copy, Debug)]
pub struct WaitingMsgCall {
    pub taskId: TaskId,
    pub addr: u64,
    pub len: usize,
    pub retAddr: u64,
}

pub struct VMSpace {
    pub pageTables: PageTables,
    pub allocator: HostPageAllocator,
    pub hostAddrTop: u64,
    pub sharedLoasdOffset: u64,
    pub vdsoAddr: u64,
    pub vcpuCount: usize,
    pub vcpuMappingDelta: usize,

    pub rng: RandGen,
    pub args: Option<Args>,
    pub pivot: bool,
    pub waitingMsgCall: Option<WaitingMsgCall>,
    pub controlSock: i32,
    pub vcpus: Vec<Arc<KVMVcpu>>,
    pub haveMembarrierGlobal: bool,
    pub haveMembarrierPrivateExpedited: bool,
}

unsafe impl Sync for VMSpace {}
unsafe impl Send for VMSpace {}

impl VMSpace {
    ///////////start of file operation//////////////////////////////////////////////
    pub fn GetOsfd(hostfd: i32) -> Option<i32> {
        return GlobalIOMgr().GetFdByHost(hostfd);
    }

    pub fn GetFdInfo(hostfd: i32) -> Option<FdInfo> {
        return GlobalIOMgr().GetByHost(hostfd);
    }

    pub fn ReadDir(dirfd: i32, addr: u64, len: usize, reset: bool) -> i64 {
        let fdInfo = match Self::GetFdInfo(dirfd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOReadDir(addr, len, reset);
    }

    pub fn Mount(&self, id: &str, rootfs: &str) -> Result<()> {
        let spec = &self.args.as_ref().unwrap().Spec;
        //let rootfs : &str = &spec.root.path;
        let cpath = format!("/{}", id);

        init_rootfs(spec, rootfs, &cpath, false)?;
        pivot_rootfs(&*rootfs)?;
        return Ok(());
    }

    pub fn PivotRoot(&self, rootfs: &str) {
        let mns = MountNs::New(rootfs.to_string());
        mns.PivotRoot();
    }

    pub fn WriteControlMsgResp(fd: i32, addr: u64, len: usize, close: bool) -> i64 {
        let buf = {
            let ptr = addr as *const u8;
            unsafe { slice::from_raw_parts(ptr, len) }
        };

        let resp: UCallResp = serde_json::from_slice(&buf[0..len]).expect("ControlMsgRet des fail");

        let usock = USocket { socket: fd };

        match usock.SendResp(&resp) {
            Err(e) => error!("ControlMsgRet send resp fail with error {:?}", e),
            Ok(()) => (),
        }

        if close {
            usock.Drop();
        }

        return 0;
    }

    pub fn VCPUCount() -> usize {
        let mut cpuCount = num_cpus::get();

        if cpuCount < 2 {
            cpuCount = 2; // at least 2 vcpu (one for host io and the other for process vcpu)
        }

        if cpuCount > MAX_VCPU_COUNT {
            cpuCount = MAX_VCPU_COUNT;
        }

        return cpuCount;
    }

    pub fn LoadProcessKernel(&mut self, processAddr: u64) -> i64 {
        let process = unsafe {
            &mut *(processAddr as * mut loader::Process)
        };
        process.ID = self.args.as_ref().unwrap().ID.to_string();
        let spec = &mut self.args.as_mut().unwrap().Spec;

        let mut cwd = spec.process.cwd.to_string();
        if cwd.len() == 0 {
            cwd = "/".to_string();
        }
        process.Cwd = cwd;

        SetConole(spec.process.terminal);
        process.Terminal = spec.process.terminal;
        process.Args.append(&mut spec.process.args);
        process.Envs.append(&mut spec.process.env);

        //todo: credential fix.
        error!("LoadProcessKernel: need to study the user mapping handling...");
        process.UID = spec.process.user.uid;
        process.GID = spec.process.user.gid;
        process
            .AdditionalGids
            .append(&mut spec.process.user.additional_gids);
        process.limitSet = CreateLimitSet(&spec)
            .expect("load limitSet fail")
            .GetInternalCopy();
        process.Caps = Capabilities(false, &spec.process.capabilities);

        process.HostName = spec.hostname.to_string();

        process.NumCpu = self.vcpuCount as u32;
        process.ExecId = Some("".to_string());

        for i in 0..process.Stdiofds.len() {
            let osfd = unsafe { dup(i as i32) as i32 };

            URING_MGR.lock().Addfd(osfd).unwrap();

            if osfd < 0 {
                return osfd as i64;
            }

            let hostfd = GlobalIOMgr().AddFile(osfd);

            process.Stdiofds[i] = hostfd;
        }
        process.Root = format!("/{}", &process.ID);
        //process.Root = "/".to_string();

        let rootfs = self.args.as_ref().unwrap().Rootfs.to_string();

        if self.pivot {
            self.PivotRoot(&rootfs);
        }

        StartSignalHandle();
        return 0;
    }

    pub fn TgKill(tgid: i32, tid: i32, signal: i32) -> i64 {
        let nr = SysCallID::sys_tgkill as usize;
        let ret = unsafe { syscall3(nr, tgid as usize, tid as usize, signal as usize) as i32 };
        return ret as _;
    }

    pub fn CreateMemfd(len: i64, flags: u32) -> i64 {
        let uid = NewUID();
        let path = format!("/tmp/memfd_{}", uid);
        let cstr = CString::New(&path);

        let nr = SysCallID::sys_memfd_create as usize;
        let fd =
            unsafe { syscall2(nr, cstr.Ptr() as *const c_char as usize, flags as usize) as i32 };

        if fd < 0 {
            return Self::GetRet(fd as i64);
        }

        let ret = unsafe { ftruncate(fd, len) };

        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Self::GetRet(ret as i64);
        }

        let hostfd = GlobalIOMgr().AddFile(fd);
        return hostfd as i64;
    }

    pub fn Fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { fallocate(fd, mode, offset, len) };

        return Self::GetRet(ret as i64);
    }

    pub fn RenameAt(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> i64 {
        let olddirfd = {
            if olddirfd > 0 {
                match Self::GetOsfd(olddirfd) {
                    Some(olddirfd) => olddirfd,
                    None => return -SysErr::EBADF as i64,
                }
            } else {
                olddirfd
            }
        };

        let newdirfd = {
            if newdirfd > 0 {
                match Self::GetOsfd(newdirfd) {
                    Some(newdirfd) => newdirfd,
                    None => return -SysErr::EBADF as i64,
                }
            } else {
                newdirfd
            }
        };

        let ret = unsafe {
            renameat(
                olddirfd,
                oldpath as *const c_char,
                newdirfd,
                newpath as *const c_char,
            )
        };

        return Self::GetRet(ret as i64);
    }

    pub fn Ftruncate(fd: i32, len: i64) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { ftruncate64(fd, len) };

        return Self::GetRet(ret as i64);
    }

    pub fn GetStr(string: u64) -> &'static str {
        let ptr = string as *const u8;
        let slice = unsafe { slice::from_raw_parts(ptr, 1024) };

        let len = {
            let mut res: usize = 0;
            for i in 0..1024 {
                if slice[i] == 0 {
                    res = i;
                    break;
                }
            }

            res
        };

        return str::from_utf8(&slice[0..len]).unwrap();
    }

    pub fn GetStrWithLen(string: u64, len: u64) -> &'static str {
        let ptr = string as *const u8;
        let slice = unsafe { slice::from_raw_parts(ptr, len as usize) };

        return str::from_utf8(&slice[0..len as usize]).unwrap();
    }

    pub fn GetStrLen(string: u64) -> i64 {
        let ptr = string as *const u8;
        let slice = unsafe { slice::from_raw_parts(ptr, 1024) };

        let len = {
            let mut res: usize = 0;
            for i in 0..1024 {
                if slice[i] == 0 {
                    res = i;
                    break;
                }
            }

            res
        };

        return (len + 1) as i64;
    }

    pub unsafe fn TryOpenHelper(dirfd: i32, name: u64) -> (i32, bool) {
        let flags = Flags::O_NOFOLLOW;
        let ret = libc::openat(
            dirfd,
            name as *const c_char,
            (flags | Flags::O_RDWR) as i32,
            0,
        );
        if ret > 0 {
            return (ret, true);
        }

        let err = Self::GetRet(ret as i64) as i32;
        if err == -SysErr::ENOENT {
            return (-SysErr::ENOENT, false);
        }

        let ret = libc::openat(
            dirfd,
            name as *const c_char,
            (flags | Flags::O_RDONLY) as i32,
            0,
        );
        if ret > 0 {
            return (ret, false);
        }

        let ret = libc::openat(
            dirfd,
            name as *const c_char,
            (flags | Flags::O_WRONLY) as i32,
            0,
        );
        if ret > 0 {
            return (ret, true);
        }

        let ret = libc::openat(
            dirfd,
            name as *const c_char,
            flags as i32 | Flags::O_PATH,
            0,
        );
        if ret > 0 {
            return (ret, false);
        }

        return (Self::GetRet(ret as i64) as i32, false);
    }

    pub fn TryOpenAt(dirfd: i32, name: u64, addr: u64) -> i64 {
        //info!("TryOpenAt: the filename is {}", Self::GetStr(name));
        let dirfd = if dirfd < 0 {
            dirfd
        } else {
            match Self::GetOsfd(dirfd) {
                Some(fd) => fd,
                None => return -SysErr::EBADF as i64,
            }
        };

        let tryOpenAt = unsafe { &mut *(addr as *mut TryOpenStruct) };

        let (fd, writeable) = unsafe { Self::TryOpenHelper(dirfd, name) };

        //error!("TryOpenAt dirfd {}, name {} ret {}", dirfd, Self::GetStr(name), fd);

        if fd < 0 {
            return fd as i64;
        }

        let ret =
            unsafe { libc::fstat(fd, tryOpenAt.fstat as *const _ as u64 as *mut stat) as i64 };

        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Self::GetRet(ret as i64);
        }

        tryOpenAt.writeable = writeable;
        let hostfd = GlobalIOMgr().AddFile(fd);

        if tryOpenAt.fstat.IsRegularFile() {
            URING_MGR.lock().Addfd(hostfd).unwrap();
        }

        return hostfd as i64;
    }

    pub fn OpenAt(dirfd: i32, name: u64, flags: i32, addr: u64) -> i64 {
        let tryOpenAt = unsafe { &mut *(addr as *mut TryOpenStruct) };

        let ret = unsafe {
            libc::openat(
                dirfd,
                name as *const c_char,
                flags,
                0,
            )
        };

        let fd = Self::GetRet(ret as i64) as i32;
        if fd < 0 {
            return fd as i64;
        }

        let ret =
            unsafe { libc::fstat(fd, tryOpenAt.fstat as *const _ as u64 as *mut stat) as i64 };

        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
        }

        let hostfd = GlobalIOMgr().AddFile(fd);

        if tryOpenAt.fstat.IsRegularFile() {
            URING_MGR.lock().Addfd(hostfd).unwrap();
        }

        return Self::GetRet(fd as i64);
    }

    pub fn CreateAt(
        dirfd: i32,
        fileName: u64,
        flags: i32,
        mode: i32,
        uid: u32,
        gid: u32,
        fstatAddr: u64,
    ) -> i32 {
        info!("CreateAt: the filename is {}, flag is {:x}, the mode is {:b}, owenr is {}:{}, dirfd is {}",
            Self::GetStr(fileName), flags, mode, uid, gid, dirfd);

        let dirfd = if dirfd < 0 {
            dirfd
        } else {
            match Self::GetOsfd(dirfd) {
                Some(fd) => fd,
                None => return -SysErr::EBADF as i32,
            }
        };

        unsafe {
            let osfd = libc::openat(
                dirfd,
                fileName as *const c_char,
                flags as c_int,
                mode as c_int,
            );
            if osfd <= 0 {
                return Self::GetRet(osfd as i64) as i32;
            }

            let ret = libc::fchown(osfd, uid, gid);
            if ret < 0 {
                libc::close(osfd);
                return Self::GetRet(ret as i64) as i32;
            }

            let ret = libc::fstat(osfd, fstatAddr as *mut stat) as i64;

            if ret < 0 {
                libc::close(osfd);
                return Self::GetRet(ret as i64) as i32;
            }

            let hostfd = GlobalIOMgr().AddFile(osfd);

            URING_MGR.lock().Addfd(osfd).unwrap();

            return hostfd;
        }
    }

    pub fn Close(fd: i32) -> i64 {
        let info = GlobalIOMgr().RemoveFd(fd);

        URING_MGR.lock().Removefd(fd).unwrap();
        let res = if info.is_some() {
            let fdInfo = info.unwrap();
            let fdInfoLock = fdInfo.lock();
            let sockInfo = fdInfoLock.sockInfo.lock().clone();
            match sockInfo {
                SockInfo::RDMADataSocket(dataSock) => {
                    GlobalRDMASvcCli().channelToSocketMappings.lock().remove(&dataSock.channelId);
                    GlobalRDMASvcCli().rdmaIdToSocketMappings.lock().remove(&dataSock.rdmaId);
                    let _res = GlobalRDMASvcCli().close(dataSock.channelId);
                }
                SockInfo::RDMAServerSocket(serverSock) => {
                    GlobalRDMASvcCli().rdmaIdToSocketMappings.lock().remove(&serverSock.rdmaId);
                    //TODO: handle server close
                    error!("ServerSock, fd: {}", fd);
                }
                _ => {
                }
            }
            0
        } else {
            -SysErr::EINVAL as i64
        };

        return res;
    }

    pub fn IORead(fd: i32, iovs: u64, iovcnt: i32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { readv(fd as c_int, iovs as *const iovec, iovcnt) as i64 };

        return Self::GetRet(ret as i64);
    }

    pub fn IOTTYRead(fd: i32, iovs: u64, iovcnt: i32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe {
            let opt: i32 = 1;
            // in some cases, tty read will blocked even after set unblock with fcntl
            // todo: this workaround, fix this
            ioctl(fd, FIONBIO, &opt);

            readv(fd as c_int, iovs as *const iovec, iovcnt) as i64
        };

        unsafe {
            let opt: i32 = 0;
            ioctl(fd, FIONBIO, &opt);
        }

        return Self::GetRet(ret as i64);
    }

    pub fn IOBufWrite(fd: i32, addr: u64, len: usize, offset: isize) -> i64 {
        PerfGoto(PerfType::BufWrite);
        defer!(PerfGofrom(PerfType::BufWrite));

        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOBufWrite(addr, len, offset);
    }

    pub fn IOWrite(fd: i32, iovs: u64, iovcnt: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOWrite(iovs, iovcnt);
    }

    pub fn UpdateWaitInfo(fd: i32, waitInfo: FdWaitInfo) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        fdInfo.UpdateWaitInfo(waitInfo);
        return 0;
    }

    pub fn IOAppend(fd: i32, iovs: u64, iovcnt: i32, fileLenAddr: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOAppend(iovs, iovcnt, fileLenAddr);
    }

    pub fn IOReadAt(fd: i32, iovs: u64, iovcnt: i32, offset: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOReadAt(iovs, iovcnt, offset);
    }

    pub fn IOWriteAt(fd: i32, iovs: u64, iovcnt: i32, offset: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOWriteAt(iovs, iovcnt, offset);
    }

    pub fn IOAccept(fd: i32, addr: u64, addrlen: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOAccept(addr, addrlen);
    }

    pub fn NewSocket(fd: i32) -> i64 {
        GlobalIOMgr().AddSocket(fd);
        URING_MGR.lock().Addfd(fd).unwrap();
        return 0;
    }

    pub fn IOConnect(fd: i32, addr: u64, addrlen: u32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOConnect(addr, addrlen);
    }

    pub fn IORecvMsg(fd: i32, msghdr: u64, flags: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IORecvMsg(msghdr, flags);
    }

    pub fn IORecvfrom(fd: i32, buf: u64, size: usize, flags: i32, addr: u64, len: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IORecvfrom(buf, size, flags, addr, len);
    }

    pub fn IOSendMsg(fd: i32, msghdr: u64, flags: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOSendMsg(msghdr, flags);
    }

    pub fn IOSendto(fd: i32, buf: u64, size: usize, flags: i32, addr: u64, len: u32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOSendto(buf, size, flags, addr, len);
    }

    pub fn Fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(info) => info,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFcntl(cmd, arg);
    }

    pub fn IoCtl(fd: i32, cmd: u64, argp: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOIoCtl(cmd, argp);
    }

    pub fn SysSync() -> i64 {
        // as quark running inside container, assume sys_sync only works for the current fs namespace
        // todo: confirm this
        unsafe { libc::sync() };

        return 0;
    }

    pub fn SyncFs(fd: i32) -> i64 {
        let osfd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { libc::syncfs(osfd) as i64 };

        return Self::GetRet(ret);
    }

    pub fn SyncFileRange(fd: i32, offset: i64, nbytes: i64, flags: u32) -> i64 {
        let osfd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { libc::sync_file_range(osfd, offset, nbytes, flags) as i64 };

        return Self::GetRet(ret);
    }

    pub fn FSync(fd: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFSync(false);
    }

    pub fn FDataSync(fd: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFSync(true);
    }

    pub fn Seek(fd: i32, offset: i64, whence: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOSeek(offset, whence);
    }

    pub fn FSetXattr(fd: i32, name: u64, value: u64, size: usize, flags: u32) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFSetXattr(name, value, size, flags);
    }

    pub fn FGetXattr(fd: i32, name: u64, value: u64, size: usize) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFGetXattr(name, value, size);
    }

    pub fn FRemoveXattr(fd: i32, name: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFRemoveXattr(name);
    }

    pub fn FListXattr(fd: i32, list: u64, size: usize) -> i64 {
        let fdInfo = match Self::GetFdInfo(fd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOFListXattr(list, size);
    }

    pub fn ReadLinkAt(dirfd: i32, path: u64, buf: u64, bufsize: u64) -> i64 {
        //info!("ReadLinkAt: the path is {}", Self::GetStr(path));

        let dirfd = {
            if dirfd == -100 {
                dirfd
            } else {
                match Self::GetOsfd(dirfd) {
                    Some(dirfd) => dirfd,
                    None => return -SysErr::EBADF as i64,
                }
            }
        };

        let res = unsafe {
            readlinkat(
                dirfd,
                path as *const c_char,
                buf as *mut c_char,
                bufsize as usize,
            )
        };
        return Self::GetRet(res as i64);
    }

    pub fn Fstat(fd: i32, buf: u64) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { libc::fstat(fd, buf as *mut stat) as i64 };

        return Self::GetRet(ret);
    }

    pub fn Getxattr(path: u64, name: u64, value: u64, size: u64) -> i64 {
        info!(
            "Getxattr: the path is {}, name is {}",
            Self::GetStr(path),
            Self::GetStr(name)
        );
        let ret = unsafe {
            getxattr(
                path as *const c_char,
                name as *const c_char,
                value as *mut c_void,
                size as usize,
            ) as i64
        };

        return Self::GetRet(ret);
    }

    pub fn Lgetxattr(path: u64, name: u64, value: u64, size: u64) -> i64 {
        info!(
            "Lgetxattr: the path is {}, name is {}",
            Self::GetStr(path),
            Self::GetStr(name)
        );
        let ret = unsafe {
            lgetxattr(
                path as *const c_char,
                name as *const c_char,
                value as *mut c_void,
                size as usize,
            ) as i64
        };

        return Self::GetRet(ret);
    }

    pub fn Fgetxattr(fd: i32, name: u64, value: u64, size: u64) -> i64 {
        let fd = Self::GetOsfd(fd).expect("fgetxattr");
        let ret = unsafe {
            fgetxattr(
                fd,
                name as *const c_char,
                value as *mut c_void,
                size as usize,
            ) as i64
        };

        return Self::GetRet(ret);
    }

    pub fn GetRet(ret: i64) -> i64 {
        if ret == -1 {
            //info!("get error, errno is {}", errno::errno().0);
            return -errno::errno().0 as i64;
        }

        return ret;
    }

    pub fn Fstatat(dirfd: i32, pathname: u64, buf: u64, flags: i32) -> i64 {
        let dirfd = {
            if dirfd > 0 {
                Self::GetOsfd(dirfd).expect("Fstatat")
            } else {
                dirfd
            }
        };

        return unsafe {
            Self::GetRet(
                libc::fstatat(dirfd, pathname as *const c_char, buf as *mut stat, flags) as i64,
            )
        };
    }

    pub fn Fstatfs(fd: i32, buf: u64) -> i64 {
        let fd = Self::GetOsfd(fd).expect("Fstatfs");

        let ret = unsafe { fstatfs(fd, buf as *mut statfs) };

        return Self::GetRet(ret as i64);
    }

    pub fn Unlinkat(dirfd: i32, pathname: u64, flags: i32) -> i64 {
        info!("Unlinkat: the pathname is {}", Self::GetStr(pathname));
        let dirfd = {
            if dirfd > 0 {
                match Self::GetOsfd(dirfd) {
                    Some(dirfd) => dirfd,
                    None => return -SysErr::EBADF as i64,
                }
            } else {
                dirfd
            }
        };

        let ret = unsafe { unlinkat(dirfd, pathname as *const c_char, flags) };

        return Self::GetRet(ret as i64);
    }

    pub fn Mkfifoat(dirfd: i32, name: u64, mode: u32, uid: u32, gid: u32) -> i64 {
        info!("Mkfifoat: the pathname is {}", Self::GetStr(name));
        let dirfd = {
            if dirfd > 0 {
                match Self::GetOsfd(dirfd) {
                    Some(dirfd) => dirfd,
                    None => return -SysErr::EBADF as i64,
                }
            } else {
                dirfd
            }
        };

        let ret = unsafe { mkfifoat(dirfd, name as *const c_char, mode as mode_t) };

        Self::ChDirOwnerat(dirfd, name, uid, gid);

        return Self::GetRet(ret as i64);
    }

    pub fn Mkdirat(dirfd: i32, pathname: u64, mode_: u32, uid: u32, gid: u32) -> i64 {
        info!("Mkdirat: the pathname is {}", Self::GetStr(pathname));

        let dirfd = {
            if dirfd > 0 {
                match Self::GetOsfd(dirfd) {
                    Some(dirfd) => dirfd,
                    None => return -SysErr::EBADF as i64,
                }
            } else {
                dirfd
            }
        };

        let ret = unsafe { mkdirat(dirfd, pathname as *const c_char, mode_ as mode_t) };

        Self::ChDirOwnerat(dirfd, pathname, uid, gid);

        return Self::GetRet(ret as i64);
    }

    pub fn ChDirOwnerat(dirfd: i32, pathname: u64, uid: u32, gid: u32) {
        unsafe {
            let ret = libc::fchownat(dirfd, pathname as *const c_char, uid, gid, 0);
            if ret < 0 {
                panic!("fchownat fail with error {}", Self::GetRet(ret as i64))
            }
        }
    }

    pub fn MSync(addr: u64, len: usize, flags: i32) -> i64 {
        let ret = unsafe { msync(addr as *mut c_void, len, flags) };

        return Self::GetRet(ret as i64);
    }

    pub fn MAdvise(addr: u64, len: usize, advise: i32) -> i64 {
        let ret = unsafe { madvise(addr as *mut c_void, len, advise) };

        return Self::GetRet(ret as i64);
    }

    pub fn FAccessAt(dirfd: i32, pathname: u64, mode: i32, flags: i32) -> i64 {
        info!("FAccessAt: the pathName is {}", Self::GetStr(pathname));
        let dirfd = {
            if dirfd == -100 {
                dirfd
            } else {
                match Self::GetOsfd(dirfd) {
                    Some(dirfd) => dirfd,
                    None => return -SysErr::EBADF as i64,
                }
            }
        };

        let ret = unsafe { faccessat(dirfd, pathname as *const c_char, mode, flags) };

        return Self::GetRet(ret as i64);
    }

    ///////////end of file operation//////////////////////////////////////////////

    ///////////start of network operation//////////////////////////////////////////////////////////////////

    pub fn Socket(domain: i32, type_: i32, protocol: i32) -> i64 {
        let fd = unsafe {
            socket(
                domain,
                type_ | SocketFlags::SOCK_NONBLOCK | SocketFlags::SOCK_CLOEXEC,
                protocol,
            )
        };

        if fd < 0 {
            return Self::GetRet(fd as i64);
        }

        let hostfd = GlobalIOMgr().AddSocket(fd);
        URING_MGR.lock().Addfd(fd).unwrap();
        return Self::GetRet(hostfd as i64);
    }

    pub fn GetSockName(sockfd: i32, addr: u64, addrlen: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOGetSockName(addr, addrlen);
    }

    pub fn GetPeerName(sockfd: i32, addr: u64, addrlen: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOGetPeerName(addr, addrlen);
    }

    pub fn GetSockOpt(sockfd: i32, level: i32, optname: i32, optval: u64, optlen: u64) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOGetSockOpt(level, optname, optval, optlen);
    }

    pub fn SetSockOpt(sockfd: i32, level: i32, optname: i32, optval: u64, optlen: u32) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOSetSockOpt(level, optname, optval, optlen);
    }

    pub fn Bind(sockfd: i32, sockaddr: u64, addrlen: u32, umask: u32) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOBind(sockaddr, addrlen, umask);
    }

    pub fn Listen(sockfd: i32, backlog: i32, block: bool) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOListen(backlog, block);
    }

    pub fn RDMAListen(sockfd: i32, backlog: i32, block: bool, acceptQueue: AcceptQueue) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.RDMAListen(backlog, block, acceptQueue);
    }

    pub fn RDMANotify(sockfd: i32, typ: RDMANotifyType) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.RDMANotify(typ);
    }

    pub fn PostRDMAConnect(msg: &'static mut PostRDMAConnect) {
        let fdInfo = match Self::GetFdInfo(msg.fd) {
            Some(fdInfo) => fdInfo,
            None => {
                msg.Finish(-SysErr::EBADF as i64);
                return;
            }
        };

        fdInfo.PostRDMAConnect(msg);
    }

    pub fn Shutdown(sockfd: i32, how: i32) -> i64 {
        let fdInfo = match Self::GetFdInfo(sockfd) {
            Some(fdInfo) => fdInfo,
            None => return -SysErr::EBADF as i64,
        };

        return fdInfo.IOShutdown(how);
    }

    ///////////end of network operation//////////////////////////////////////////////////////////////////
    pub fn ReadControlMsg(fd: i32, addr: u64) -> i64 {
        match super::ucall::ucall_server::ReadControlMsg(fd) {
            Err(_e) => return -1,
            Ok(msg) => {
                let controlMsg = unsafe {
                    &mut *(addr as * mut ControlMsg)
                };
                *controlMsg = msg;
                return 0; 
            }
        }
    }

    pub fn SchedGetAffinity(pid: i32, cpuSetSize: u64, mask: u64) -> i64 {
        //todo: fix this
        //let pid = 0;

        let ret = unsafe {
            sched_getaffinity(pid as pid_t, cpuSetSize as size_t, mask as *mut cpu_set_t)
        };

        //todo: fix this.
        if ret == 0 {
            return 8;
        } else {
            Self::GetRet(ret as i64)
        }
    }

    pub fn GetTimeOfDay(tv: u64, tz: u64) -> i64 {
        //let res = unsafe{ gettimeofday(tv as *mut timeval, tz as *mut timezone) };
        //return Self::GetRet(res as i64)

        let nr = SysCallID::sys_gettimeofday as usize;
        unsafe {
            let res = syscall2(nr, tv as usize, tz as usize) as i64;
            //error!("finish GetTimeOfDay");
            return res;
        }
    }

    pub fn GetRandom(&mut self, buf: u64, len: u64, _flags: u32) -> i64 {
        unsafe {
            let slice = slice::from_raw_parts_mut(buf as *mut u8, len as usize);
            self.rng.Fill(slice);
        }

        return len as i64;
    }

    pub fn GetRandomU8(&mut self) -> u8 {
        let mut data: [u8; 1] = [0; 1];
        self.rng.Fill(&mut data);
        return data[0];
    }

    pub fn RandomVcpuMapping(&mut self) {
        let delta = self.GetRandomU8() as usize;
        self.vcpuMappingDelta = delta % Self::VCPUCount();
        error!("RandomVcpuMapping {}", self.vcpuMappingDelta);
    }

    pub fn ComputeVcpuCoreId(&self, threadId: usize) -> usize {
        let id = (threadId + self.vcpuMappingDelta) % Self::VCPUCount();

        return id;
    }

    pub fn Fchdir(fd: i32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { fchdir(fd) };

        return Self::GetRet(ret as i64);
    }

    pub fn Sysinfo(info: u64) -> i64 {
        unsafe {
            return Self::GetRet(sysinfo(info as *mut sysinfo) as i64);
        }
    }

    pub fn Fadvise(fd: i32, offset: u64, len: u64, advice: i32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { posix_fadvise(fd, offset as i64, len as i64, advice) };

        return Self::GetRet(ret as i64);
    }

    pub fn Mlock2(addr: u64, len: u64, flags: u32) -> i64 {
        let nr = SysCallID::sys_mlock2 as usize;
        let ret = unsafe { syscall3(nr, addr as usize, len as usize, flags as usize) as i64 };

        return Self::GetRet(ret as i64);
    }

    pub fn MUnlock(addr: u64, len: u64) -> i64 {
        let ret = unsafe { munlock(addr as *const c_void, len as size_t) };

        return Self::GetRet(ret as i64);
    }

    pub fn Chown(pathname: u64, owner: u32, group: u32) -> i64 {
        info!("Chown: the pathname is {}", Self::GetStr(pathname));

        let ret = unsafe { chown(pathname as *const c_char, owner, group) };

        return Self::GetRet(ret as i64);
    }

    pub fn FChown(fd: i32, owner: u32, group: u32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { fchown(fd, owner, group) };

        return Self::GetRet(ret as i64);
    }

    pub fn Chmod(pathname: u64, mode: u32) -> i64 {
        let ret = unsafe { chmod(pathname as *const c_char, mode as mode_t) };

        return Self::GetRet(ret as i64);
    }

    pub fn Fchmod(fd: i32, mode: u32) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { fchmod(fd, mode as mode_t) };

        return Self::GetRet(ret as i64);
    }

    pub fn EventfdWrite(fd: i32) -> i64 {
        let val: u64 = 8;

        let ret = unsafe { write(fd, &val as *const _ as _, 8) };

        return Self::GetRet(ret as i64);
    }

    pub fn NonBlockingPoll(fd: i32, mask: EventMask) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let mut e = pollfd {
            fd: fd,
            events: mask as i16,
            revents: 0,
        };

        loop {
            let ret = unsafe { poll(&mut e, 1, 0) };

            let ret = Self::GetRet(ret as i64) as i32;
            // Interrupted by signal, try again.
            if ret == -SysErr::EINTR {
                continue;
            }

            // If an error occur we'll conservatively say the FD is ready for
            // whatever is being checked.
            if ret < 0 {
                return mask as i64;
            }

            // If no FDs were returned, it wasn't ready for anything.
            if ret == 0 {
                return 0;
            }

            return e.revents as i64;
        }
    }

    pub fn NewTmpfile(dir: bool, addr: u64) -> i64 {
        let mut td = temp_dir();

        let file_name = format!("{}", Uuid::new_v4());
        td.push(file_name);

        let fd  = if dir {
            let folder = td.into_os_string().into_string().unwrap();
            let cstr = CString::New(&folder);
            let ret = unsafe {
                libc::mkdir(cstr.Ptr() as *const c_char, 0o777)
            };

            if ret != 0 {
                return Self::GetRet(ret as i64);
            }

            let fd = unsafe {
                libc::openat(-100, cstr.Ptr() as *const c_char, libc::O_DIRECTORY | libc::O_RDONLY, 0o777)
            };

            Self::GetRet(fd as i64) as i32
        } else {
            let file = fs::File::create(td).expect("tmp file create fail");
            file.into_raw_fd()
        };

        let ret = unsafe { fstat(fd, addr as *mut stat) };

        if ret < 0 {
            unsafe {
                close(fd);
            }

            return Self::GetRet(ret as i64);
        }

        let guestfd = GlobalIOMgr().AddFile(fd);

        return guestfd as i64;
    }

    pub fn NewFifo() -> i64 {
        let uid = NewUID();
        let path = format!("/tmp/fifo_{}", uid);
        let cstr = CString::New(&path);
        let ret = unsafe { mkfifo(cstr.Ptr() as *const c_char, 0o666) };

        error!("NewFifo apth is {}, id is {}", path, ret);

        if ret < 0 {
            return Self::GetRet(ret as i64);
        }

        return uid as i64;
    }

    pub fn NewTmpfsFile(typ: TmpfsFileType, addr: u64) -> i64 {
        match typ {
            TmpfsFileType::Dir => Self::NewTmpfile(true, addr),
            TmpfsFileType::File => Self::NewTmpfile(false, addr),
        }
    }

    pub fn Statm(buf: u64) -> i64 {
        const STATM: &str = "/proc/self/statm";
        let contents = fs::read_to_string(STATM).expect("Something went wrong reading the file");

        let output = scan!(&contents, char::is_whitespace, u64, u64);
        let mut statm = unsafe { &mut *(buf as *mut StatmInfo) };

        statm.vss = output.0.unwrap();
        statm.rss = output.1.unwrap();
        return 0;
    }

    pub fn HostEpollWaitProcess() -> i64 {
        let ret = FD_NOTIFIER.HostEpollWait();
        return ret;
    }

    pub fn HostID(axArg: u32, cxArg: u32) -> (u32, u32, u32, u32) {
        let mut ax: u32 = axArg;
        let bx: u32;
        let mut cx: u32 = cxArg;
        let dx: u32;
        unsafe {
            asm!("
              CPUID
              mov edi, ebx
            ",
            inout("eax") ax,
            out("edi") bx,
            inout("ecx") cx,
            out("edx") dx,
            );
        }

        return (ax, bx, cx, dx);
    }

    pub fn SymLinkAt(oldpath: u64, newdirfd: i32, newpath: u64) -> i64 {
        let newdirfd = match Self::GetOsfd(newdirfd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret =
            unsafe { symlinkat(oldpath as *const c_char, newdirfd, newpath as *const c_char) };

        return Self::GetRet(ret as i64);
    }

    pub fn LinkAt(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64, flags: i32) -> i64 {
        let newdirfd = match Self::GetOsfd(newdirfd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let olddirfd = match Self::GetOsfd(olddirfd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret =
            unsafe { linkat(olddirfd, oldpath as *const c_char, newdirfd, newpath as *const c_char, flags) };

        return Self::GetRet(ret as i64);
    }

    pub fn Futimens(fd: i32, times: u64) -> i64 {
        let fd = match Self::GetOsfd(fd) {
            Some(fd) => fd,
            None => return -SysErr::EBADF as i64,
        };

        let ret = unsafe { futimens(fd, times as *const timespec) };

        return Self::GetRet(ret as i64);
    }

    //map kernel table
    pub fn KernelMap(
        &mut self,
        start: Addr,
        end: Addr,
        physical: Addr,
        flags: PageTableFlags,
    ) -> Result<bool> {
        error!("KernelMap start is {:x}, end is {:x}", start.0, end.0);
        return self
            .pageTables
            .Map(start, end, physical, flags, &mut self.allocator, true);
    }

    pub fn KernelMapHugeTable(
        &mut self,
        start: Addr,
        end: Addr,
        physical: Addr,
        flags: PageTableFlags,
    ) -> Result<bool> {
        error!("KernelMap1G start is {:x}, end is {:x}", start.0, end.0);
        return self
            .pageTables
            .MapWith1G(start, end, physical, flags, &mut self.allocator, true);
    }

    pub fn PrintStr(phAddr: u64) {
        unsafe {
            info!(
                "the Str: {} ",
                str::from_utf8_unchecked(slice::from_raw_parts(
                    phAddr as *const u8,
                    strlen(phAddr as *const i8) + 1
                ))
            );
        }
    }

    pub fn u32_to_CUdevice_attribute(val: u32) -> CUdevice_attribute {
        let attrib: CUdevice_attribute = match val {
            1 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
            2 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X,
            3 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y,
            4 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z,
            5 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X,
            6 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y,
            7 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z,
            8 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK,
            9 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY,
            10 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_WARP_SIZE,
            11 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_PITCH,
            12 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK,
            13 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CLOCK_RATE,
            14 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT,
            15 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_GPU_OVERLAP,
            16 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
            17 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT,
            18 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_INTEGRATED,
            19 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY,
            20 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_MODE,
            21 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_WIDTH,
            22 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_WIDTH,
            23 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_HEIGHT,
            24 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH,
            25 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT,
            26 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH,
            27 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_WIDTH,
            28 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_HEIGHT,
            29 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_LAYERS,
            30 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_SURFACE_ALIGNMENT,
            31 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CONCURRENT_KERNELS,
            32 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_ECC_ENABLED,
            33 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_PCI_BUS_ID,
            34 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID,
            35 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_TCC_DRIVER,
            36 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE,
            37 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH,
            38 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_L2_CACHE_SIZE,
            39 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_MULTIPROCESSOR,
            40 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT,
            41 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING,
            42 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_WIDTH,
            43 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_LAYERS,
            44 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_TEX2D_GATHER,
            45 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_WIDTH,
            46 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_HEIGHT,
            47 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH_ALTERNATE,
            48 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT_ALTERNATE,
            49 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH_ALTERNATE,
            50 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID,
            51 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_TEXTURE_PITCH_ALIGNMENT,
            52 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_WIDTH,
            53 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_WIDTH,
            54 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_LAYERS,
            55 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_WIDTH,
            56 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_WIDTH,
            57 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_HEIGHT,
            58 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_WIDTH,
            59 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_HEIGHT,
            60 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_DEPTH,
            61 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_WIDTH,
            62 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_LAYERS,
            63 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_WIDTH,
            64 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_HEIGHT,
            65 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_LAYERS,
            66 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_WIDTH,
            67 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_WIDTH,
            68 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_LAYERS,
            69 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LINEAR_WIDTH,
            70 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_WIDTH,
            71 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_HEIGHT,
            72 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_PITCH,
            73 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_WIDTH,
            74 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_HEIGHT,
            75 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
            76 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
            77 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_MIPMAPPED_WIDTH,
            78 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_STREAM_PRIORITIES_SUPPORTED,
            79 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_GLOBAL_L1_CACHE_SUPPORTED,
            80 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_LOCAL_L1_CACHE_SUPPORTED,
            81 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_MULTIPROCESSOR,
            82 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_MULTIPROCESSOR,
            83 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MANAGED_MEMORY,
            84 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD,
            85 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD_GROUP_ID,
            86 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_HOST_NATIVE_ATOMIC_SUPPORTED,
            87 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_SINGLE_TO_DOUBLE_PRECISION_PERF_RATIO,
            88 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS,
            89 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS,
            90 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_PREEMPTION_SUPPORTED,
            91 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM,
            92 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_USE_STREAM_MEM_OPS,
            93 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_USE_64_BIT_STREAM_MEM_OPS,
            94 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_USE_STREAM_WAIT_VALUE_NOR,
            95 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COOPERATIVE_LAUNCH,
            96 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COOPERATIVE_MULTI_DEVICE_LAUNCH,
            97 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK_OPTIN,
            98 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CAN_FLUSH_REMOTE_WRITES,
            99 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_HOST_REGISTER_SUPPORTED,
            100 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES,
            101 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_DIRECT_MANAGED_MEM_ACCESS_FROM_HOST,
            102 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED,
            103 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED,
            104 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_WIN32_HANDLE_SUPPORTED,
            105 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_WIN32_KMT_HANDLE_SUPPORTED,
            106 => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX,
            _ => CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX,
        };
        return attrib;
    }

    pub fn Proxy(cmd: u64, addrIn: u64, addrOut: u64) -> i64 {
        use super::qlib::proxy::*;
        let cmd : Command = unsafe { core::mem::transmute(cmd as u64) };
        match cmd {
            Command::Cmd1 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd1In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret: cudaError_enum = unsafe { cuInit(dataIn.val) };
                error!("cuInit, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd2 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd2In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd2Out)
                };

                let mut dev: CUdevice = 0; 
                let ret = unsafe { cuDeviceGet(&mut dev, dataIn.val) };
                error!("cuDeviceGet, ret is {:?}", ret);

                dataOut.val_i32 = dev as i32;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd3 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd3In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd3Out)
                };

                let mut ctx: CUcontext = ptr::null_mut();
                let ret = unsafe { cuCtxCreate_v2(&mut ctx, dataIn.flags, dataIn.dev) };
                error!("cuCtxCreate_v2, ret is {:?}, ctx is {:?}", ret, ctx);

                dataOut.val = ctx as u64;
                dataOut.CUresult = ret as u32;
            }
            Command::Cmd4 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd4In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut dptr: CUdeviceptr = 0;
                let ret = unsafe { cuMemAlloc_v2(&mut dptr, dataIn.val as usize) };
                error!("cuMemAlloc_v2, ret is {:?}, devptr={:x}", ret, dptr);

                dataOut.val_u64 = dptr;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd5 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd5In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret = unsafe { cuMemcpyHtoD_v2(dataIn.devptr, dataIn.hostptr as *mut c_void, dataIn.bytecount as usize) };
                error!("cuMemcpyHtoD_v2, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd6 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd5In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };
                
                let ret = unsafe { cuMemcpyDtoH_v2(dataIn.hostptr as *mut c_void, dataIn.devptr, dataIn.bytecount as usize) };
                error!("cuMemcpyDtoH_v2, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd7 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd7In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd3Out)
                };

                let mut module: CUmodule = ptr::null_mut();
                let ret = unsafe { cuModuleLoad(&mut module, dataIn.ptr as *const ::std::os::raw::c_char) };
                error!("cuModuleLoad, ret is {:?}", ret);

                dataOut.val = module as u64;
                dataOut.CUresult = ret as u32;
            }
            Command::Cmd8 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd5In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd3Out)
                };

                let mut function: CUfunction = ptr::null_mut();
                let ret = unsafe { 
                    cuModuleGetFunction(&mut function, dataIn.devptr as CUmodule, dataIn.hostptr as *const ::std::os::raw::c_char) 
                };
                error!("cuModuleGetFunction, ret is {:?}, CUfunction={:x}", ret, function as u64);

                dataOut.val = function as u64;
                dataOut.CUresult = ret as u32;
            }
            Command::Cmd9 => {
                let mut dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd9InOut)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                dataIn.totalParamSize = unsafe {
                    *((dataIn.func + 0x278 as u64) as * const u32)
                };

                dataIn.numParams = unsafe {
                    *((dataIn.func + 0x2ac as u64) as * const u32)
                };

                let addr = unsafe {
                    *((dataIn.func + 0x2a0 as u64) as * const u64)
                };

                let offsets = unsafe {
                    &mut *(dataIn.ptr as * mut [u32;32])
                };

                for i in 0..dataIn.numParams {
                    let val = unsafe {*((addr + (4*i) as u64) as * const u32)};
                    offsets[i as usize] = val;
                }

                dataOut.val = 0u32;
            }
            Command::Cmd10 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd10In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret = unsafe { 
                    cuLaunchKernel(
                        dataIn.func as CUfunction, 
                        dataIn.gridDimX,
                        dataIn.gridDimY,
                        dataIn.gridDimZ,
                        dataIn.blockDimX,
                        dataIn.blockDimY,
                        dataIn.blockDimZ,
                        dataIn.sharedMemBytes,
                        dataIn.stream as CUstream,
                        dataIn.params as *mut *mut libc::c_void,
                        dataIn.extra as *mut *mut libc::c_void
                    )
                };
                error!("cuLaunchKernel, ret is {:?}", ret);

                dataOut.val = ret as u32;          
            }
            Command::Cmd11 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd4In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret: cudaError_enum = unsafe { cuMemFree_v2(dataIn.val) };
                error!("cuMemFree_v2, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd12 => {
                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd2Out)
                };

                let mut version: i32 = 0; 
                let ret = unsafe { cuDriverGetVersion(&mut version) };
                error!("cuDriverGetVersion, ret is {:?}", ret);

                dataOut.val_i32 = version;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd13 => {
                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd2Out)
                };

                let mut count: i32 = 0; 
                let ret = unsafe { cuDeviceGetCount(&mut count) };
                error!("cuDeviceGetCount, ret is {:?}", ret);

                dataOut.val_i32 = count;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd14 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd3In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd3Out)
                };

                let mut pExportTable: *const ::std::os::raw::c_void = ptr::null_mut();

                const TABLE0ID: CUuuid = CUuuid {
                    bytes: [
                        0x6b, -43i8, -5i8, 0x6c, 0x5b, -12i8, -25i8, 0x4a, -119i8, 
                        -121i8, -39i8, 0x39, 0x12, -3i8, -99i8, -7i8,
                    ],
                };

                let ret = unsafe { cuGetExportTable(&mut pExportTable as *mut *const ::std::os::raw::c_void, &TABLE0ID) };
                error!("cuGetExportTable, ret is {:?}, pExportTable={:?}", ret, pExportTable);

                let addr: u64 = unsafe {
                    *((pExportTable as *const u64).offset(2))
                };

                error!("pExportTable[2]=0x{:x}", addr);

                let funcptr = addr as *const ();
                let code: extern "C" fn(*mut CUcontext, CUdevice) -> CUresult = unsafe { std::mem::transmute(funcptr) };
                let mut ctx: CUcontext = ptr::null_mut();
                let ret = (code)(&mut ctx, dataIn.dev);
                error!("hidden_0_1, ret is {:?}, ctx is {:?}", ret, ctx);

                dataOut.val = ctx as u64;
                dataOut.CUresult = ret as u32;
            }
            Command::Cmd15 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd15In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret = unsafe {
                    cuDeviceGetName(
                        dataIn.buf as *mut ::std::os::raw::c_char,
                        dataIn.len as ::std::os::raw::c_int,
                        dataIn.dev as CUdevice
                    )
                };

                error!("cuDeviceGetName, ret is {:?}", ret);
                dataOut.val = ret as u32;
            }
            Command::Cmd16 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd2In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut totalMem: usize = 0;
                let ret = unsafe {
                    cuDeviceTotalMem_v2(
                        &mut totalMem,
                        dataIn.val,
                    )
                };

                dataOut.val_u32 = ret as u32;
                dataOut.val_u64 = totalMem as u64;
            }
            Command::Cmd17 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd3In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd2Out)
                };

                let mut i: i32 = 0;
                let attrib: CUdevice_attribute = Self::u32_to_CUdevice_attribute(dataIn.flags);

                let ret = unsafe {
                    cuDeviceGetAttribute(
                        &mut i as *mut ::std::os::raw::c_int,
                        attrib,
                        dataIn.dev,
                    )
                };

                dataOut.val_u32 = ret as u32;
                dataOut.val_i32 = i;
            }
            Command::Cmd18 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd18In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let buffer: &mut [::std::os::raw::c_char; 16] = unsafe {
                    &mut *(dataIn.val_u64 as *mut [::std::os::raw::c_char; 16])
                };

                let mut id: CUuuid = CUuuid { bytes: [0; 16] }; 
                let ret = unsafe {
                    cuDeviceGetUuid(
                        &mut id as *mut CUuuid,
                        dataIn.val_u32 as CUdevice
                    )
                };
                error!("cuDeviceGetUuid, ret is {:?}", ret);

                buffer[..16].clone_from_slice(&id.bytes);
                dataOut.val = ret as u32;
            }
            Command::Cmd19 => {
                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd2Out)
                };

                let mut dev: CUdevice = 0; 
                let ret = unsafe { cuCtxGetDevice(&mut dev) };
                error!("cuCtxGetDevice, ret is {:?}", ret);

                dataOut.val_i32 = dev as i32;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd20 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd4In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let ret = unsafe { cuCtxSetCurrent(dataIn.val as CUcontext) };
                error!("cuCtxSetCurrent, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd21 => {
                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut ctx: CUcontext = ptr::null_mut();
                let ret = unsafe { cuCtxGetCurrent(&mut ctx) };
                error!("cuCtxGetCurrent, ret is {:?}", ret);

                dataOut.val_u64 = ctx as u64;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd22 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd4In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let mut pExportTable: *const ::std::os::raw::c_void = ptr::null_mut();

                const TABLE0ID: CUuuid = CUuuid {
                    bytes: [
                        0x6b, -43i8, -5i8, 0x6c, 0x5b, -12i8, -25i8, 0x4a, -119i8, 
                        -121i8, -39i8, 0x39, 0x12, -3i8, -99i8, -7i8,
                    ],
                };

                let ret = unsafe { cuGetExportTable(&mut pExportTable as *mut *const ::std::os::raw::c_void, &TABLE0ID) };
                error!("cuGetExportTable, ret is {:?}, pExportTable={:?}", ret, pExportTable);

                let addr: u64 = unsafe {
                    *((pExportTable as *const u64).offset(7))
                };

                error!("pExportTable[7]=0x{:x}", addr);

                let funcptr = addr as *const ();
                let code: extern "C" fn(u64) -> CUresult = unsafe { std::mem::transmute(funcptr) };
                let ret = (code)(dataIn.val);
                error!("hidden_0_6, ret is {:?}", ret);

                dataOut.val = ret as u32;
            }
            Command::Cmd23 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd18In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let tableID: CUuuid;

                if dataIn.val_u32 == 0 {
                    tableID = CUuuid {
                        bytes: [
                            0x6b, -43i8, -5i8, 0x6c, 0x5b, -12i8, -25i8, 0x4a, -119i8, 
                            -121i8, -39i8, 0x39, 0x12, -3i8, -99i8, -7i8,
                        ],
                    };
                }
                else if dataIn.val_u32 == 1 {
                    tableID = CUuuid {
                        bytes: [
                            -96i8, -108i8, 0x79, -116i8, 0x2e, 0x74, 0x2e, 0x74, -109i8, 
                            -14i8, 0x08, 0x00, 0x20, 0x0c, 0x0a, 0x66,
                        ],
                    };
                }
                else if dataIn.val_u32 == 2 {
                    tableID = CUuuid {
                        bytes: [
                            0x42, -40i8, 0x5a, -127i8, 0x23, -10i8, -53i8, 0x47, -126i8, 
                            -104i8, -10i8, -25i8, -118i8, 0x3a, -20i8, -36i8,
                        ],
                    };
                }
                else {
                    tableID = CUuuid {
                        bytes: [
                            -58i8, -109i8, 0x33, 0x6e, 0x11, 0x21, -33i8, 0x11, -88i8, 
                            -61i8, 0x68, -13i8, 0x55, -40i8, -107i8, -109i8,
                        ],
                    };
                    error!("table No. = {}, arg2={}", dataIn.val_u32, dataIn.val_u64);
                }

                let mut pExportTable: *const ::std::os::raw::c_void = ptr::null_mut();

                let ret = unsafe { cuGetExportTable(&mut pExportTable as *mut *const ::std::os::raw::c_void, &tableID) };
                error!("cuGetExportTable, ret is {:?}, pExportTable={:?}", ret, pExportTable);

                let addr: u64 = unsafe {
                    *((pExportTable as *const u64).offset(2))
                };

                let funcptr = addr as *const ();
                let code: extern "C" fn(*mut CUcontext, i32, *mut *const ::std::os::raw::c_void) -> CUresult = unsafe { std::mem::transmute(funcptr) };
                let mut ctx: CUcontext = ptr::null_mut();
                let ret = (code)(&mut ctx, 0, &mut pExportTable as *mut *const ::std::os::raw::c_void);
                error!("hidden_3_2, ret is {:?}, ctx is {:?}", ret, ctx);

                dataOut.val_u64 = ctx as u64;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd24 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd2In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut ctx: CUcontext = ptr::null_mut();
                let ret = unsafe { cuDevicePrimaryCtxRetain(&mut ctx, dataIn.val) };
                error!("cuDevicePrimaryCtxRetain, ret is {:?}", ret);

                dataOut.val_u64 = ctx as u64;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd25 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd25In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd1Out)
                };

                let tableID: CUuuid;

                if dataIn.val_u32 == 0 {
                    tableID = CUuuid {
                        bytes: [
                            0x6b, -43i8, -5i8, 0x6c, 0x5b, -12i8, -25i8, 0x4a, -119i8, 
                            -121i8, -39i8, 0x39, 0x12, -3i8, -99i8, -7i8,
                        ],
                    };
                }
                else if dataIn.val_u32 == 1 {
                    tableID = CUuuid {
                        bytes: [
                            -96i8, -108i8, 0x79, -116i8, 0x2e, 0x74, 0x2e, 0x74, -109i8, 
                            -14i8, 0x08, 0x00, 0x20, 0x0c, 0x0a, 0x66,
                        ],
                    };
                }
                else if dataIn.val_u32 == 2 {
                    tableID = CUuuid {
                        bytes: [
                            0x42, -40i8, 0x5a, -127i8, 0x23, -10i8, -53i8, 0x47, -126i8, 
                            -104i8, -10i8, -25i8, -118i8, 0x3a, -20i8, -36i8,
                        ],
                    };
                }
                else {
                    tableID = CUuuid {
                        bytes: [
                            -58i8, -109i8, 0x33, 0x6e, 0x11, 0x21, -33i8, 0x11, -88i8, 
                            -61i8, 0x68, -13i8, 0x55, -40i8, -107i8, -109i8,
                        ],
                    };
                    error!("table No. = {}, ptr={}, i32={}", dataIn.val_u32, dataIn.val_u64, dataIn.val_i32);
                }

                let mut pExportTable: *const ::std::os::raw::c_void = ptr::null_mut();

                let ret = unsafe { cuGetExportTable(&mut pExportTable as *mut *const ::std::os::raw::c_void, &tableID) };
                error!("cuGetExportTable, ret is {:?}, pExportTable={:?}", ret, pExportTable);

                let addr: u64 = unsafe {
                    *((pExportTable as *const u64).offset(0))
                };

                let funcptr = addr as *const ();
                let code: extern "C" fn(i32, *mut *const ::std::os::raw::c_void, *mut CUcontext) -> CUresult = unsafe { std::mem::transmute(funcptr) };
                let mut ctx: CUcontext = dataIn.val_u64 as CUcontext;
                let ret = (code)(dataIn.val_i32, &mut pExportTable as *mut *const ::std::os::raw::c_void, &mut ctx);
                error!("hidden_3_0, ret is {:?}, ctx is {:?}", ret, ctx);

                dataOut.val = ret as u32;
            }
            Command::Cmd26 => {
                let dataIn = unsafe {
                    &mut *(addrIn as * mut Cmd26In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut pExportTable: *const ::std::os::raw::c_void = ptr::null_mut();

                const TABLE0ID: CUuuid = CUuuid {
                    bytes: [
                        0x6b, -43i8, -5i8, 0x6c, 0x5b, -12i8, -25i8, 0x4a, -119i8, 
                        -121i8, -39i8, 0x39, 0x12, -3i8, -99i8, -7i8,
                    ],
                };

                let ret = unsafe { cuGetExportTable(&mut pExportTable as *mut *const ::std::os::raw::c_void, &TABLE0ID) };
                error!("cuGetExportTable, ret is {:?}, pExportTable={:?}", ret, pExportTable);

                let addr: u64 = unsafe {
                    *((pExportTable as *const u64).offset(6))
                };

                let funcptr = addr as *const ();
                let mut module: CUmodule = ptr::null_mut();
                let mut arg2: u64 = dataIn.val1_u64;
                let code: extern "C" fn(&mut CUmodule, *mut u64, u64, u64, i32) -> CUresult = unsafe { std::mem::transmute(funcptr) };
                let ret = (code)(&mut module, &mut arg2, dataIn.val2_u64, dataIn.val3_u64, dataIn.val4_i32);
                error!("hidden_0_5, ret is {:?}, arg2={:x}, arg3={:x}, arg4={:x}, arg5={}", 
                ret, arg2, dataIn.val2_u64, dataIn.val3_u64, dataIn.val4_i32);

                dataOut.val_u64 = module as u64;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd27 => {
                let dataIn = unsafe {
                    &*(addrIn as * const Cmd4In)
                };

                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd4Out)
                };

                let mut dptr = ptr::null_mut();
                let ret = unsafe { cudaMalloc(&mut dptr as *mut *mut c_void, dataIn.val as usize) };
                error!("cudaMalloc, ret is {:?}", ret);

                dataOut.val_u64 = dptr as u64;
                dataOut.val_u32 = ret as u32;
            }
            Command::Cmd28 => {
                let dataOut = unsafe {
                    &mut *(addrOut as * mut Cmd28Out)
                };

                unsafe {
                    let lib = match libloading::Library::new("/usr/local/cuda/targets/x86_64-linux/lib/libcudart.so.11.0") {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Cannot load libcuda.so: {}", e);
                            return 0;
                        }
                    };
                
                    let __cudaRegisterFatBinary: libloading::Symbol<unsafe extern fn(u64) -> u64> = 
                                                 match lib.get(b"__cudaRegisterFatBinary") {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Could not load function __cudaRegisterFatBinary: {}", e);
                            return 0;
                        }
                    };

                    let ret = __cudaRegisterFatBinary(addrIn);
                    error!("__cudaRegisterFatBinary, ret is {:?}", ret);

                    dataOut.val = ret;
                };
            }
        }

        return 0;
    }


    pub fn SwapInPage(addr: u64) -> i64 {
        match SHARE_SPACE.hiberMgr.SwapIn(addr) {
            Ok(_) => return 0,
            Err(Error::SysError(e)) => return e as i64,
            _ => panic!("imposible")
        }
    }

    pub fn UnblockFd(fd: i32) {
        unsafe {
            let flags = fcntl(fd, Cmd::F_GETFL, 0);
            let ret = fcntl(fd, Cmd::F_SETFL, flags | Flags::O_NONBLOCK);
            assert!(ret == 0, "UnblockFd fail");
        }
    }

    pub fn BlockFd(fd: i32) {
        unsafe {
            let flags = fcntl(fd, Cmd::F_GETFL, 0);
            let ret = fcntl(fd, Cmd::F_SETFL, flags & !Flags::O_NONBLOCK);
            assert!(ret == 0, "UnblockFd fail");
        }
    }

    pub fn GetStdfds(addr: u64) -> i64 {
        let ptr = addr as *mut i32;
        let stdfds = unsafe { slice::from_raw_parts_mut(ptr, 3) };

        for i in 0..stdfds.len() {
            let osfd = unsafe { dup(i as i32) as i32 };

            if osfd < 0 {
                return osfd as i64;
            }

            Self::UnblockFd(osfd);

            let hostfd = GlobalIOMgr().AddFile(osfd);
            stdfds[i] = hostfd;
        }

        return 0;
    }

    pub fn Signal(&self, signal: SignalArgs) {
        SignalProcess(&signal);
        //SHARE_SPACE.AQHostInputCall(&HostInputMsg::Signal(signal));
    }

    pub fn LibcFstat(osfd: i32) -> Result<LibcStat> {
        let mut stat = LibcStat::default();
        let ret = unsafe { fstat(osfd, &mut stat as *mut _ as u64 as *mut stat) };

        if ret < 0 {
            info!("can't fstat osfd {}", osfd);
            return Err(Error::SysError(errno::errno().0));
        }

        //Self::LibcStatx(osfd);

        return Ok(stat);
    }

    pub fn LibcStatx(osfd: i32) {
        let statx = Statx::default();
        let addr: i8 = 0;
        let ret = unsafe {
            libc::statx(
                osfd,
                &addr as *const c_char,
                libc::AT_EMPTY_PATH,
                libc::STATX_BASIC_STATS,
                &statx as *const _ as u64 as *mut statx,
            )
        };

        error!(
            "LibcStatx osfd is {} ret is {} error is {}",
            osfd,
            ret,
            errno::errno().0
        );
    }

    pub fn GetVcpuFreq(&self) -> i64 {
        let freq = self.vcpus[0].vcpu.get_tsc_khz().unwrap() * 1000;
        return freq as i64;
    }

    pub fn Membarrier(cmd: i32) -> i32 {
        let nr = SysCallID::sys_membarrier as usize;
        let ret = unsafe {
            syscall3(
                nr,
                cmd as usize,
                0 as usize, /*flag*/
                0 as usize, /*unused*/
            ) as i32
        };
        return ret as _;
    }

    pub fn HostMemoryBarrier() -> i64 {
        let haveMembarrierPrivateExpedited = VMS.lock().haveMembarrierPrivateExpedited;
        let cmd = if haveMembarrierPrivateExpedited {
            MEMBARRIER_CMD_PRIVATE_EXPEDITED
        } else {
            MEMBARRIER_CMD_GLOBAL
        };

        return Self::Membarrier(cmd) as _;
    }

    //return (haveMembarrierGlobal, haveMembarrierPrivateExpedited)
    pub fn MembarrierInit() -> (bool, bool) {
        let supported = Self::Membarrier(MEMBARRIER_CMD_QUERY);
        if supported < 0 {
            return (false, false);
        }

        let mut haveMembarrierGlobal = false;
        let mut haveMembarrierPrivateExpedited = false;
        // We don't use MEMBARRIER_CMD_GLOBAL_EXPEDITED because this sends IPIs to
        // all CPUs running tasks that have previously invoked
        // MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, which presents a DOS risk.
        // (MEMBARRIER_CMD_GLOBAL is synchronize_rcu(), i.e. it waits for an RCU
        // grace period to elapse without bothering other CPUs.
        // MEMBARRIER_CMD_PRIVATE_EXPEDITED sends IPIs only to CPUs running tasks
        // sharing the caller's MM.)
        if supported & MEMBARRIER_CMD_GLOBAL != 0 {
            haveMembarrierGlobal = true;
        }

        let req = MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
        if supported & req == req {
            let ret = Self::Membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED);
            if ret >= 0 {
                haveMembarrierPrivateExpedited = true;
            }
        }

        return (haveMembarrierGlobal, haveMembarrierPrivateExpedited);
    }

    pub fn Init() -> Self {
        let (haveMembarrierGlobal, haveMembarrierPrivateExpedited) = Self::MembarrierInit();

        return VMSpace {
            allocator: HostPageAllocator::New(),
            pageTables: PageTables::default(),
            hostAddrTop: 0,
            sharedLoasdOffset: 0x0000_5555_0000_0000,
            vdsoAddr: 0,
            vcpuCount: 0,
            vcpuMappingDelta: 0,
            rng: RandGen::Init(),
            args: None,
            pivot: false,
            waitingMsgCall: None,
            controlSock: -1,
            vcpus: Vec::new(),
            haveMembarrierGlobal: haveMembarrierGlobal,
            haveMembarrierPrivateExpedited: haveMembarrierPrivateExpedited,
        };
    }
}

impl PostRDMAConnect {
    pub fn Finish(&mut self, ret: i64) {
        self.ret = ret;
        SHARE_SPACE
            .scheduler
            .ScheduleQ(self.taskId, self.taskId.Queue(), true)
    }

    pub fn ToRef(addr: u64) -> &'static mut Self {
        let msgRef = unsafe { &mut *(addr as *mut Self) };

        return msgRef;
    }
}
