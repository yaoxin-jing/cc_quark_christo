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

use crate::qlib::mutex::*;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::ops::Deref;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::Ordering;

//use super::super::*;
use crate::qlib::mem::block::Iovs;
use super::super::super::super::common::*;
use super::super::super::super::fileinfo::*;
use super::super::super::super::linux::time::Timeval;
use super::super::super::super::linux_def::*;
use super::super::super::super::socket_buf::*;
use super::super::super::fs::attr::*;
use super::super::super::fs::dentry::*;
use super::super::super::fs::dirent::*;
use super::super::super::fs::file::*;
use super::super::super::fs::flags::*;
use super::super::super::fs::host::hostinodeop::*;
use super::super::super::guestfdnotifier::*;
use super::super::super::kernel::async_wait::*;
use super::super::super::kernel::fd_table::*;
use super::super::super::kernel::kernel::GetKernel;
use super::super::super::kernel::time::*;
use super::super::super::kernel::waiter::*;
use super::super::super::GlobalIOMgr;
use super::super::super::task::*;
use super::super::super::tcpip::tcpip::*;
use super::super::super::Kernel;
use super::super::super::Kernel::HostSpace;
use super::super::super::IOURING;
use super::super::control::*;
use super::super::socket::*;
use super::socket::*;

#[repr(u64)]
#[derive(Clone)]
pub enum SockState {
    TCPInit,                      // Init TCP Socket, no listen and no connect
    TCPConnecting,                 // TCP socket is connecting
    TCPServer(AcceptQueue),        // Uring TCP Server socket, when socket start to listen
    TCPData(Arc<SocketBuff>),
}

impl fmt::Debug for SockState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SockState::TCPInit => write!(f, "SocketBufType::TCPInit"),
            SockState::TCPConnecting => write!(f, "SocketBufType::Connecting"),
            SockState::TCPServer(_) => write!(f, "SocketBufType::TCPServer"),
            SockState::TCPData(_) => write!(f, "SocketBufType::TCPData"),
        }
    }
}

impl SockState {
    pub fn Accept(&self, socketBuf: Arc<SocketBuff>) -> Self {
        match self {
            SockState::TCPServer(_) => return SockState::TCPData(socketBuf),
            _ => {
                panic!("SocketBufType::Accept unexpect type {:?}", self)
            }
        }
    }

    pub fn Connect(&self) -> Self {
        match self {
            Self::TCPInit => return self.ConnectType(),
            _ => {
                panic!("SockState::Connect unexpect type {:?}", self)
            }
        }
    }

    fn ConnectType(&self) -> Self {
        let socketBuf = Arc::new(SocketBuff::Init(MemoryDef::DEFAULT_BUF_PAGE_COUNT));
        return Self::TCPData(socketBuf);
    }
}

pub fn newAsyncSocketFile(
    task: &Task,
    family: i32,
    fd: i32,
    stype: i32,
    nonblock: bool,
    state: SockState,
    addr: Option<Vec<u8>>,
) -> Result<File> {
    let dirent = NewSocketDirent(task, SOCKET_DEVICE.clone(), fd)?;
    let inode = dirent.Inode();
    let iops = inode.lock().InodeOp.clone();
    let hostiops = iops.as_any().downcast_ref::<HostInodeOp>().unwrap();
    let s = AsyncSocketOperations::New(
        family,
        fd,
        stype,
        hostiops.Queue(),
        hostiops.clone(),
        state,
        addr,
    )?;

    hostiops.DisableDrop();

    let file = File::New(
        &dirent,
        &FileFlags {
            NonBlocking: nonblock,
            Read: true,
            Write: true,
            ..Default::default()
        },
        s,
    );

    GetKernel().sockets.AddSocket(&file);
    return Ok(file)
}

pub struct AsyncSocketInfoIntern {
    pub fd: i32,
    pub queue: Queue,
    pub state: QMutex<SockState>,
    pub writelock: QMutex<()>,
}

impl Drop for AsyncSocketInfoIntern {
    fn drop(&mut self) {
        HostSpace::Close(self.fd);
    }
}

#[derive(Clone)]
pub struct AsyncSocketInfo(Arc<AsyncSocketInfoIntern>);

impl Deref for AsyncSocketInfo {
    type Target = Arc<AsyncSocketInfoIntern>;

    fn deref(&self) -> &Arc<AsyncSocketInfoIntern> {
        &self.0
    }
}

impl AsyncSocketInfo {
    pub fn New(fd: i32, queue: Queue, state: SockState) -> Self {
        let intern = AsyncSocketInfoIntern {
            fd,
            queue: queue,
            state: QMutex::new(state),
            writelock: QMutex::new(())
        };

        return Self(Arc::new(intern))
    }

    pub fn SetState(&self, state: SockState) {
        *self.state.lock() = state;
    }


    pub fn SocketBufState(&self) -> SockState {
        return self.state.lock().clone();
    }
}

pub struct AsyncSocketOperationsIntern {
    pub send: AtomicI64,
    pub recv: AtomicI64,
    pub family: i32,
    pub stype: i32,
    pub socketInfo: AsyncSocketInfo,
    pub remoteAddr: QMutex<Option<SockAddr>>,
    pub hostops: HostInodeOp,
    passInq: AtomicBool,
}

#[derive(Clone)]
pub struct AsyncSocketOperationsWeak(pub Weak<AsyncSocketOperationsIntern>);

impl AsyncSocketOperationsWeak {
    pub fn Upgrade(&self) -> Option<AsyncSocketOperations> {
        let f = match self.0.upgrade() {
            None => return None,
            Some(f) => f,
        };

        return Some(AsyncSocketOperations(f));
    }
}

#[derive(Clone)]
pub struct AsyncSocketOperations(Arc<AsyncSocketOperationsIntern>);

impl AsyncSocketOperations {
    pub fn New(
        family: i32,
        fd: i32,
        stype: i32,
        queue: Queue,
        hostops: HostInodeOp,
        state: SockState,
        addr: Option<Vec<u8>>,
    ) -> Result<Self> {
        let addr = match addr {
            None => None,
            Some(v) => {
                if v.len() == 0 {
                    None
                } else {
                    Some(GetAddr(v[0] as i16, &v[0..v.len()]).unwrap())
                }
            }
        };

        let ret = AsyncSocketOperationsIntern {
            send: AtomicI64::new(0),
            recv: AtomicI64::new(0),
            family,
            stype,
            socketInfo: AsyncSocketInfo::New(fd, queue, state),
            remoteAddr: QMutex::new(addr),
            hostops: hostops,
            passInq: AtomicBool::new(false),
        };

        let ret = Self(Arc::new(ret));

        let fdInfo = GlobalIOMgr().GetByHost(fd).expect("AsyncSocketOperations new fail");
        *fdInfo.lock().sockInfo.lock() = SockInfo::AsyncSocket(ret.socketInfo.clone());

        let defaultMask = ret.DefaultMask();
        ret.Updatefd(defaultMask);
        return Ok(ret);
    }

}

impl Deref for AsyncSocketOperations {
    type Target = Arc<AsyncSocketOperationsIntern>;

    fn deref(&self) -> &Arc<AsyncSocketOperationsIntern> {
        &self.0
    }
}

impl AsyncSocketOperations {
    pub fn Downgrade(&self) -> AsyncSocketOperationsWeak {
        return AsyncSocketOperationsWeak(Arc::downgrade(&self.0));
    }

    pub fn SetRemoteAddr(&self, addr: Vec<u8>) -> Result<()> {
        let addr = GetAddr(addr[0] as i16, &addr[0..addr.len()])?;

        *self.remoteAddr.lock() = Some(addr);
        return Ok(());
    }

    pub fn GetRemoteAddr(&self) -> Option<Vec<u8>> {
        return match *self.remoteAddr.lock() {
            None => None,
            Some(ref v) => Some(v.ToVec().unwrap()),
        };
    }

    pub fn SocketBuf(&self) -> Arc<SocketBuff> {
        match self.socketInfo.SocketBufState() {
            SockState::TCPData(b) => return b,
            _ => panic!(
                "SocketBufType::None has no SockBuff {:?}",
                self.socketInfo.SocketBufState()
            ),
        }
    }

    pub fn DefaultMask(&self) -> EventMask {
        match self.socketInfo.SocketBufState() {
            SockState::TCPInit => return 0,
            SockState::TCPConnecting => return EVENT_OUT | EVENT_ERR | EVENT_HUP,
            SockState::TCPServer(_) => return EVENT_IN | EVENT_ERR | EVENT_HUP,
            SockState::TCPData(_) => return EVENT_IN | EVENT_ERR | EVENT_HUP,
        }
    }

    pub fn Updatefd(&self, mask: EventMask) {
        let fd = self.socketInfo.fd;
        UpdateFDDirect(fd, mask).unwrap();
    }

    pub fn UpdateFDMask(&self, mask: EventMask) {
        let fd = self.socketInfo.fd;
        UpdateFDMask(fd, mask).unwrap();
    }

    pub fn UpdateFDUnmask(&self, mask: EventMask) {
        let fd = self.socketInfo.fd;
        UpdateFDUnmask(fd, mask).unwrap();
    }

    pub fn AcceptData(&self, acceptQueue: &AcceptQueue) -> Result<AcceptItem> {
        let (trigger, acceptItem) = acceptQueue.lock().DeqSocket();
        if trigger {
            self.UpdateFDMask(EVENT_IN);
        }

        return acceptItem
    }

    fn prepareControlMessage(&self, controlDataLen: usize) -> (i32, Vec<u8>) {
        // shortcut for no controldata wanted
        if controlDataLen == 0 {
            return (0, Vec::new());
        }

        let mut controlData: Vec<u8> = vec![0; controlDataLen];
        if self.passInq.load(Ordering::Relaxed) {
            let inqMessage = ControlMessageTCPInq {
                Size: self.SocketBuf().readBuf.lock().AvailableDataSize() as u32,
            };

            let (remaining, updated_flags) = inqMessage.EncodeInto(&mut controlData[..], 0);
            let remainSize = remaining.len();
            controlData.resize(controlDataLen - remainSize, 0);
            return (updated_flags, controlData);
        } else {
            return (0, Vec::new());
        }
    }


    pub fn ReadData(&self, task: &Task, dsts: &mut [IoVec], peek: bool) -> Result<i64> {
        let (trigger, cnt) = self.SocketBuf().Readv(task, dsts, peek)?;

        if trigger {
            self.UpdateFDMask(EVENT_IN);
        }

        return Ok(cnt as i64);
    }

    pub fn WriteData(&self, task: &Task, srcs: &[IoVec]) -> Result<i64> {
        let size = IoVec::NumBytes(srcs);
        if size == 0 {
            return Ok(0)
        }

        let (count, writeBuf) = self.SocketBuf().Writev(task, srcs)?;

        if let Some(_) = writeBuf {
            HostSpace::AsyncSocketWrite(self.socketInfo.fd)
        }

        return Ok(count as i64);

    }
}

pub const SIZEOF_SOCKADDR: usize = SocketSize::SIZEOF_SOCKADDR_INET6;

impl Waitable for AsyncSocketOperations {
    fn AsyncReadiness(&self, _task: &Task, mask: EventMask, wait: &MultiWait) -> Future<EventMask> {
        let fd = self.socketInfo.fd;
        let future = IOURING.UnblockPollAdd(fd, mask as u32, wait);
        return future;
    }

    fn Readiness(&self, _task: &Task, mask: EventMask) -> EventMask {
        let state = self.socketInfo.SocketBufState();
        match state {
            SockState::TCPInit => return 0,
            SockState::TCPConnecting => return 0,
            SockState::TCPServer(queue) => {
                return queue.lock().Events() & mask;
            }
            SockState::TCPData(queue) =>{
                return queue.Events() & mask;
            }
        }
    }

    fn EventRegister(&self, task: &Task, e: &WaitEntry, mask: EventMask) {
        let queue = self.socketInfo.queue.clone();
        queue.EventRegister(task, e, mask);
    }

    fn EventUnregister(&self, task: &Task, e: &WaitEntry) {
        let queue = self.socketInfo.queue.clone();
        queue.EventUnregister(task, e);
    }
}

impl SpliceOperations for AsyncSocketOperations {}

impl FileOperations for AsyncSocketOperations {
    fn as_any(&self) -> &Any {
        return self;
    }

    fn FopsType(&self) -> FileOpsType {
        return FileOpsType::SocketOperations;
    }

    fn Seekable(&self) -> bool {
        return false;
    }

    fn Seek(
        &self,
        _task: &Task,
        _f: &File,
        _whence: i32,
        _current: i64,
        _offset: i64,
    ) -> Result<i64> {
        return Err(Error::SysError(SysErr::ESPIPE));
    }

    fn ReadDir(
        &self,
        _task: &Task,
        _f: &File,
        _offset: i64,
        _serializer: &mut DentrySerializer,
    ) -> Result<i64> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn ReadAt(
        &self,
        task: &Task,
        _f: &File,
        dsts: &mut [IoVec],
        _offset: i64,
        _blocking: bool,
    ) -> Result<i64> {
        return self.ReadData(task, dsts, false);
    }

    fn WriteAt(
        &self,
        task: &Task,
        _f: &File,  
        srcs: &[IoVec],
        _offset: i64,
        _blocking: bool,
    ) -> Result<i64> {
        return self.WriteData(task, srcs)
    }

    fn Append(&self, task: &Task, f: &File, srcs: &[IoVec]) -> Result<(i64, i64)> {
        let n = self.WriteAt(task, f, srcs, 0, false)?;
        return Ok((n, 0));
    }

    fn Fsync(
        &self,
        _task: &Task,
        _f: &File,
        _start: i64,
        _end: i64,
        _syncType: SyncType,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::EINVAL));
    }

    fn Flush(&self, _task: &Task, _f: &File) -> Result<()> {
        return Ok(());
    }

    fn UnstableAttr(&self, task: &Task, f: &File) -> Result<UnstableAttr> {
        let inode = f.Dirent.Inode();
        return inode.UnstableAttr(task);
    }

    fn Ioctl(&self, task: &Task, _f: &File, _fd: i32, request: u64, val: u64) -> Result<()> {
        let flags = request as i32;

        let hostfd = self.socketInfo.fd;
        match flags as u64 {
            LibcConst::SIOCGIFFLAGS
            | LibcConst::SIOCGIFBRDADDR
            | LibcConst::SIOCGIFDSTADDR
            | LibcConst::SIOCGIFHWADDR
            | LibcConst::SIOCGIFINDEX
            | LibcConst::SIOCGIFMAP
            | LibcConst::SIOCGIFMETRIC
            | LibcConst::SIOCGIFMTU
            | LibcConst::SIOCGIFNAME
            | LibcConst::SIOCGIFNETMASK
            | LibcConst::SIOCGIFTXQLEN => {
                let addr = val;
                HostIoctlIFReq(task, hostfd, request, addr)?;

                return Ok(());
            }
            LibcConst::SIOCGIFCONF => {
                let addr = val;
                HostIoctlIFConf(task, hostfd, request, addr)?;

                return Ok(());
            }
            LibcConst::TIOCINQ => {
                let tmp: i32 = 0;
                let res = Kernel::HostSpace::IoCtl(self.socketInfo.fd, request, &tmp as *const _ as u64);
                if res < 0 {
                    return Err(Error::SysError(-res as i32));
                }
                task.CopyOutObj(&tmp, val)?;
                return Ok(());
            }
            _ => {
                let tmp: i32 = 0;
                let res = Kernel::HostSpace::IoCtl(self.socketInfo.fd, request, &tmp as *const _ as u64);
                if res < 0 {
                    return Err(Error::SysError(-res as i32));
                }
                task.CopyOutObj(&tmp, val)?;
                return Ok(());
            }
        }
    }

    fn IterateDir(
        &self,
        _task: &Task,
        _d: &Dirent,
        _dirCtx: &mut DirCtx,
        _offset: i32,
    ) -> (i32, Result<i64>) {
        return (0, Err(Error::SysError(SysErr::ENOTDIR)));
    }

    fn Mappable(&self) -> Result<MMappable> {
        return Err(Error::SysError(SysErr::ENODEV));
    }
}


impl SockOperations for AsyncSocketOperations {
    fn Connect(&self, task: &Task, sockaddr: &[u8], _blocking: bool) -> Result<i64> {
        let mut socketaddr = sockaddr;

        if (self.family == AFType::AF_INET || self.family == AFType::AF_INET6)
            && socketaddr.len() > SIZEOF_SOCKADDR
            {
                socketaddr = &socketaddr[..SIZEOF_SOCKADDR]
            }

        let res = Kernel::HostSpace::IOConnect(
            self.socketInfo.fd,
            &socketaddr[0] as *const _ as u64,
            socketaddr.len() as u32,
        ) as i32;

        let blocking = true;
        if res != 0 {
            if -res != SysErr::EINPROGRESS || !blocking {
                return Err(Error::SysError(-res));
            }

            /*if -res != SysErr::EINPROGRESS {
                return Err(Error::SysError(-res));
            }

            if !blocking {
                self.SetRemoteAddr(socketaddr.to_vec())?;
                *self.state.lock() = SockState::TCPConnecting;
                return Err(Error::SysError(-res));
            }*/

            self.socketInfo.SetState(SockState::TCPConnecting);

            //todo: which one is more efficent?
            let general = task.blocker.generalEntry.clone();
            self.EventRegister(task, &general, EVENT_OUT);
            self.Updatefd(EVENT_OUT | EVENT_HUP | EVENT_ERR);
            defer!({
                self.EventUnregister(task, &general);
                self.Updatefd(0);
            });

            if self.Readiness(task, WRITEABLE_EVENT) == 0 {
                match task.blocker.BlockWithMonoTimer(true, None) {
                    Err(Error::ErrInterrupted) => {
                        return Err(Error::SysError(SysErr::ERESTARTSYS));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                    _ => (),
                }
            }
        }

        let mut val: i32 = 0;
        let len: i32 = 4;
        let res = HostSpace::GetSockOpt(
            self.socketInfo.fd,
            LibcConst::SOL_SOCKET as i32,
            LibcConst::SO_ERROR as i32,
            &mut val as *mut i32 as u64,
            &len as *const i32 as u64,
        ) as i32;

        if res < 0 {
            return Err(Error::SysError(-res));
        }

        if val != 0 {
            return Err(Error::SysError(val as i32));
        }

        self.SetRemoteAddr(socketaddr.to_vec())?;
        let sockbuf = Arc::new(SocketBuff::Init(MemoryDef::DEFAULT_BUF_PAGE_COUNT));
        self.socketInfo.SetState(SockState::TCPData(sockbuf));
        let defaultMask = self.DefaultMask();
        self.Updatefd(defaultMask);
        return Ok(0);
    }

    fn Accept(
        &self,
        task: &Task,
        addr: &mut [u8],
        addrlen: &mut u32,
        flags: i32,
        blocking: bool,
    ) -> Result<i64> {
        let acceptQueue = match self.socketInfo.SocketBufState() {
            SockState::TCPServer(ref queue) => queue.clone(),
            _ => {
                return Err(Error::SysError(SysErr::EINVAL));
            }
        };

        let mut acceptItem = AcceptItem::default();
        if !blocking {
            let ai = self.AcceptData(&acceptQueue);

            match ai {
                Err(Error::SysError(SysErr::EAGAIN)) => {
                    if !blocking {
                        return Err(Error::SysError(SysErr::EAGAIN));
                    }
                }
                Err(e) => return Err(e),
                Ok(item) => {
                    acceptItem = item;
                }
            }
        } else {
            let general = task.blocker.generalEntry.clone();
            self.EventRegister(task, &general, EVENT_IN);
            defer!(self.EventUnregister(task, &general));

            loop {
                let ai = self.AcceptData(&acceptQueue);

                match ai {
                    Err(Error::SysError(SysErr::EAGAIN)) => (),
                    Err(e) => return Err(e),
                    Ok(item) => {
                        acceptItem = item;
                        break;
                    }
                }
                match task.blocker.BlockWithMonoTimer(true, None) {
                    Err(e) => {
                        return Err(e);
                    }
                    _ => (),
                }
            }
        }

        let mut len: usize = acceptItem.addr.data.len();
        if addr.len() > 0 {
            len = core::cmp::min(
                core::cmp::min(acceptItem.len as usize, addr.len()),
                acceptItem.addr.data.len(),
            );
            for i in 0..len {
                addr[i] = acceptItem.addr.data[i];
            }

            *addrlen = len as u32;
        }

        let fd = acceptItem.fd;

        let remoteAddr = &acceptItem.addr.data[0..len];
        let state = self.socketInfo.SocketBufState().Accept(acceptItem.sockBuf.clone());

        let file = newAsyncSocketFile(
            task,
            self.family,
            fd as i32,
            self.stype,
            flags & SocketFlags::SOCK_NONBLOCK != 0,
            state,
            Some(remoteAddr.to_vec()),
        )?;

        let fdFlags = FDFlags {
            CloseOnExec: flags & SocketFlags::SOCK_CLOEXEC != 0,
        };

        let fd = task.NewFDFrom(0, &Arc::new(file), &fdFlags)?;
        return Ok(fd as i64);
    }

    fn Bind(&self, task: &Task, sockaddr: &[u8]) -> Result<i64> {
        let mut socketaddr = sockaddr;

        info!(
        "hostinet socket bind {:?}, addr is {:?}",
        self.family, socketaddr
        );
        if (self.family == AFType::AF_INET || self.family == AFType::AF_INET6)
            && socketaddr.len() > SIZEOF_SOCKADDR
            {
                socketaddr = &socketaddr[..SIZEOF_SOCKADDR]
            }

        let res = Kernel::HostSpace::Bind(
            self.socketInfo.fd,
            &socketaddr[0] as *const _ as u64,
            socketaddr.len() as u32,
            task.Umask(),
        );
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        return Ok(res);
    }

    fn Listen(&self, _task: &Task, backlog: i32) -> Result<i64> {
        let len = if backlog <= 0 {
            5
        } else {
            backlog
        };

        let res = Kernel::HostSpace::Listen(self.socketInfo.fd, len, false);

        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        let acceptQueue = match self.socketInfo.SocketBufState() {
            SockState::TCPServer(q) => {
                q.lock().SetQueueLen(len as usize);
                return Ok(0);
            }
            _ => AcceptQueue::default(), // panic?
        };

        acceptQueue.lock().SetQueueLen(len as usize);
        self.socketInfo.SetState(SockState::TCPServer(acceptQueue));

        self.Updatefd(EVENT_IN | EVENT_ERR | EVENT_HUP);
        return Ok(res);
    }

    fn Shutdown(&self, task: &Task, how: i32) -> Result<i64> {
        let how = how as u64;

        if self.SocketBuf().HasWriteData() {
            self.SocketBuf().SetPendingWriteShutdown();
            let general = task.blocker.generalEntry.clone();
            self.EventRegister(task, &general, EVENT_PENDING_SHUTDOWN);
            defer!(self.EventUnregister(task, &general));

            while self.SocketBuf().HasWriteData() {
                task.blocker.BlockGeneralOnly();
            }
        }

        if how == LibcConst::SHUT_RD || how == LibcConst::SHUT_WR || how == LibcConst::SHUT_RDWR {
            let res = Kernel::HostSpace::Shutdown(self.socketInfo.fd, how as i32);
            if res < 0 {
                return Err(Error::SysError(-res as i32));
            }

            return Ok(res);
        }

        return Err(Error::SysError(SysErr::EINVAL));
    }

    fn GetSockOpt(&self, _task: &Task, level: i32, name: i32, opt: &mut [u8]) -> Result<i64> {
        /*
        let optlen = match level as u64 {
            LibcConst::SOL_IPV6 => {
                match name as u64 {
                    LibcConst::IPV6_V6ONLY => SocketSize::SIZEOF_INT32,
                    LibcConst::IPV6_TCLASS => SocketSize::SIZEOF_INfAT32,
                    _ => 0,
                }
            }
            LibcConst::SOL_SOCKET => {
                match name as u64 {
                    LibcConst::SO_ERROR
                    | LibcConst::SO_KEEPALIVE
                    | LibcConst::SO_SNDBUF
                    | LibcConst::SO_RCVBUF
                    | LibcConst::SO_REUSEADDR
                    | LibcConst::SO_TYPE => SocketSize::SIZEOF_INT32,
                    LibcConst::SO_LINGER => SocketSize::SIZEOF_LINGER,
                    _ => 0,
                }
            }
            LibcConst::SOL_TCP => {
                match name as u64 {
                    LibcConst::TCP_NODELAY => SocketSize::SIZEOF_INT32,
                    LibcConst::TCP_INFO => SocketSize::SIZEOF_TCPINFO,
                    _ => 0,
                }
            }
            LibcConst::SOL_IP => {
                match name as u64 {
                    LibcConst::IP_TTL => SocketSize::SIZEOF_INT32,
                    LibcConst::IP_TOS => SocketSize::SIZEOF_INT32,
                    _ => 0,
                }
            }
            _ => 0,
        };

        if optlen == 0 {
            return Err(Error::SysError(SysErr::ENOPROTOOPT))
        }

        let bufferSize = opt.len();

        if bufferSize < optlen {
            // provide special handling for options like IP_TOS, which allow inadequate buffer for optval
            match name as u64 {
                LibcConst::IP_TOS => {
                    let res = if bufferSize == 0 {
                        // dirty, any better way?
                        Kernel::HostSpace::GetSockOpt(self.fd, level, name, &bufferSize as *const _ as u64, &bufferSize as *const _ as u64)
                    } else {
                        Kernel::HostSpace::GetSockOpt(self.fd, level, name, &opt[0] as *const _ as u64, &bufferSize as *const _ as u64)
                    };
                    if res < 0 {
                        return Err(Error::SysError(-res as i32))
                    }
                    // if optlen < sizeof(i32), the return of getsockopt will be of sizeof(i8)
                    return Ok(bufferSize as i64)
                },
                _ => return Err(Error::SysError(SysErr::EINVAL))
            };
        };

        let opt = &opt[..optlen];
        let res = Kernel::HostSpace::GetSockOpt(self.fd, level, name, &opt[0] as *const _ as u64, &optlen as *const _ as u64);
        if res < 0 {
            return Err(Error::SysError(-res as i32))
        }

        return Ok(optlen as i64)
        */

        let mut optLen = opt.len();
        let res = if optLen == 0 {
            Kernel::HostSpace::GetSockOpt(
                self.socketInfo.fd,
                level,
                name,
                ptr::null::<u8>() as u64,
                &mut optLen as *mut _ as u64,
            )
        } else {
            Kernel::HostSpace::GetSockOpt(
                self.socketInfo.fd,
                level,
                name,
                &mut opt[0] as *mut _ as u64,
                &mut optLen as *mut _ as u64,
            )
        };

        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        return Ok(optLen as i64);
    }

    fn SetSockOpt(&self, task: &Task, level: i32, name: i32, opt: &[u8]) -> Result<i64> {
        if (level as u64) == LibcConst::SOL_SOCKET && (name as u64) == LibcConst::SO_SNDTIMEO {
            if opt.len() >= SocketSize::SIZEOF_TIMEVAL {
                let timeVal = task.CopyInObj::<Timeval>(&opt[0] as *const _ as u64)?;
                self.SetSendTimeout(timeVal.ToDuration() as i64);
            } else {
                //TODO: to be aligned with Linux, Linux allows shorter length for this flag.
                return Err(Error::SysError(SysErr::EINVAL));
            }
        }

        if (level as u64) == LibcConst::SOL_SOCKET && (name as u64) == LibcConst::SO_RCVTIMEO {
            if opt.len() >= SocketSize::SIZEOF_TIMEVAL {
                let timeVal = task.CopyInObj::<Timeval>(&opt[0] as *const _ as u64)?;
                self.SetRecvTimeout(timeVal.ToDuration() as i64);
            } else {
                //TODO: to be aligned with Linux, Linux allows shorter length for this flag.
                return Err(Error::SysError(SysErr::EINVAL));
            }
        }

        // TCP_INQ is bound to buffer implementation
        if (level as u64) == LibcConst::SOL_TCP && (name as u64) == LibcConst::TCP_INQ {
            let val = unsafe { *(&opt[0] as *const _ as u64 as *const i32) };
            if val == 1 {
                self.passInq.store(true, Ordering::Relaxed);
            } else {
                self.passInq.store(false, Ordering::Relaxed);
            }
        }

        let optLen = opt.len();
        let res = if optLen == 0 {
            Kernel::HostSpace::SetSockOpt(
                self.socketInfo.fd,
                level,
                name,
                ptr::null::<u8>() as u64,
                optLen as u32,
            )
        } else {
            Kernel::HostSpace::SetSockOpt(
                self.socketInfo.fd,
                level,
                name,
                &opt[0] as *const _ as u64,
                optLen as u32,
            )

        };

        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        return Ok(res);
    }

    fn GetSockName(&self, _task: &Task, socketaddr: &mut [u8]) -> Result<i64> {
        let len = socketaddr.len() as i32;

        let res = Kernel::HostSpace::GetSockName(
            self.socketInfo.fd,
            &socketaddr[0] as *const _ as u64,
            &len as *const _ as u64,
        );
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        return Ok(len as i64);
    }

    fn GetPeerName(&self, _task: &Task, socketaddr: &mut [u8]) -> Result<i64> {
        let len = socketaddr.len() as i32;
        let res = Kernel::HostSpace::GetPeerName(
            self.socketInfo.fd,
            &socketaddr[0] as *const _ as u64,
            &len as *const _ as u64,
        );
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        return Ok(len as i64);
    }

    fn RecvMsg(
        &self,
        task: &Task,
        dsts: &mut [IoVec],
        flags: i32,
        deadline: Option<Time>,
        senderRequested: bool,
        _controlDataLen: usize,
    ) -> Result<(i64, i32, Option<(SockAddr, usize)>, Vec<u8>)> {

        //todo: we don't support MSG_ERRQUEUE
        if flags
            & !(MsgType::MSG_DONTWAIT
            | MsgType::MSG_PEEK
            | MsgType::MSG_TRUNC
            | MsgType::MSG_CTRUNC
            | MsgType::MSG_WAITALL)
            != 0
            {
                return Err(Error::SysError(SysErr::EINVAL));
            }

        let waitall = (flags & MsgType::MSG_WAITALL) != 0;
        let dontwait = (flags & MsgType::MSG_DONTWAIT) != 0;
        let trunc = (flags & MsgType::MSG_TRUNC) != 0;
        let peek = (flags & MsgType::MSG_PEEK) != 0;

        let controlDataLen = 0;

        if self.SocketBuf().RClosed() {
            let senderAddr = if senderRequested {
                let addr = self.remoteAddr.lock().as_ref().unwrap().clone();
                let l = addr.Len();
                Some((addr, l))
            } else {
                None
            };

            let (retFlags, controlData) = self.prepareControlMessage(controlDataLen);
            return Ok((0 as i64, retFlags, senderAddr, controlData));
        }

        let len = IoVec::NumBytes(dsts);
        let data = if trunc {
            Some(Iovs(dsts).Data())
        } else {
            None
        };

        let mut iovs = dsts;

        let mut count = 0;
        let mut tmp;

        let general = task.blocker.generalEntry.clone();
        self.EventRegister(task, &general, EVENT_READ);
        defer!(self.EventUnregister(task, &general));

        'main: loop {
            loop {
                match self.ReadData(task, iovs, peek) {
                    Err(Error::SysError(SysErr::EWOULDBLOCK)) => {
                        if count > 0 {
                            if dontwait || !waitall {
                                break 'main;
                            }
                        }

                        if count == len as i64 {
                            break 'main;
                        }

                        if count == 0 && dontwait {
                            return Err(Error::SysError(SysErr::EWOULDBLOCK));
                        }

                        break;
                    }
                    Err(e) => {
                        if count > 0 {
                            break 'main;
                        }
                        return Err(e);
                    }
                    Ok(n) => {
                        if n == 0 {
                            break 'main;
                        }

                        count += n;
                        if count == len as i64 || peek {
                            break 'main;
                        }

                        tmp = Iovs(iovs).DropFirst(n as usize);
                        iovs = &mut tmp;
                    }
                };
            }

            match task.blocker.BlockWithMonoTimer(true, deadline) {
                Err(e) => {
                    if count > 0 {
                        break 'main;
                    }
                    match e {
                        Error::SysError(SysErr::ETIMEDOUT) => {
                            return Err(Error::SysError(SysErr::EAGAIN));
                        }
                        Error::ErrInterrupted => {
                            return Err(Error::SysError(SysErr::ERESTARTSYS));
                        }
                        _ => {
                            return Err(e);
                        }
                    }
                }
                _ => (),
            }
        }

        let senderAddr = if senderRequested {
            let addr = self.remoteAddr.lock().as_ref().unwrap().clone();
            let l = addr.Len();
            Some((addr, l))
        } else {
            None
        };

        if trunc {
            task.mm.ZeroDataOutToIovs(task, &data.unwrap(), count as usize, false)?;
        }

        let (retFlags, controlData) = self.prepareControlMessage(controlDataLen);
        return Ok((count as i64, retFlags, senderAddr, controlData));

    }

    fn SendMsg(
        &self,
        task: &Task,
        srcs: &[IoVec],
        flags: i32,
        msgHdr: &mut MsgHdr,
        deadline: Option<Time>,
    ) -> Result<i64> {
        if self.SocketBuf().WClosed() {
            return Err(Error::SysError(SysErr::EPIPE))
        }

        if msgHdr.msgName != 0 || msgHdr.msgControl != 0 {
            panic!("Hostnet Socketbuf doesn't supprot MsgHdr");
        }

        let len = Iovs(srcs).Count();
        let mut count = 0;
        let mut srcs = srcs;
        let mut tmp;
        let general = task.blocker.generalEntry.clone();
        self.EventRegister(task, &general, EVENT_WRITE);
        defer!(self.EventUnregister(task, &general));

        loop {
            loop {
                match self.WriteData(task, srcs) {
                    Err(Error::SysError(SysErr::EWOULDBLOCK)) => {
                        if flags & MsgType::MSG_DONTWAIT != 0 {
                            if count > 0 {
                                return Ok(count);
                            }
                            return Err(Error::SysError(SysErr::EWOULDBLOCK));
                        }

                        if count > 0 {
                            return Ok(count);
                        }

                        if flags & MsgType::MSG_DONTWAIT != 0 {
                            return Err(Error::SysError(SysErr::EWOULDBLOCK));
                        }

                        break;
                    }
                    Err(e) => {
                        if count > 0 {
                            return Ok(count);
                        }

                        return Err(e);
                    }
                    Ok(n) => {
                        count += n;
                        if count == len as i64 {
                            return Ok(count);
                        }
                        tmp = Iovs(srcs).DropFirst(n as usize);
                        srcs = &mut tmp;
                    }
                }
            }

            match task.blocker.BlockWithMonoTimer(true, deadline) {
                Err(Error::SysError(SysErr::ETIMEDOUT)) => {
                    if count > 0 {
                        return Ok(count);
                    }
                    return Err(Error::SysError(SysErr::EWOULDBLOCK));
                }
                Err(e) => {
                    if count > 0 {
                        return Ok(count);
                    }
                    return Err(e);
                }
                _ => (),
            }
        }
    }

    fn SetRecvTimeout(&self, ns: i64) {
        self.recv.store(ns, Ordering::Relaxed)
    }

    fn SetSendTimeout(&self, ns: i64) {
        self.send.store(ns, Ordering::Relaxed)
    }

    fn RecvTimeout(&self) -> i64 {
        return self.recv.load(Ordering::Relaxed);
    }

    fn SendTimeout(&self) -> i64 {
        return self.send.load(Ordering::Relaxed);
    }

    fn State(&self) -> u32 {
        let mut info = TCPInfo::default();
        let mut len = SocketSize::SIZEOF_TCPINFO;

        let ret = HostSpace::GetSockOpt(self.socketInfo.fd,
                                        LibcConst::SOL_TCP as _,
                                        LibcConst::TCP_INFO as _,
                                        &mut info as * mut _ as u64,
                                        &mut len as * mut _ as u64) as i32;

        if ret < 0 {
            if ret != -SysErr::ENOPROTOOPT {
                error!("fail to Failed to get TCP socket info from {} with error {}", self.socketInfo.fd, ret);

                // For non-TCP sockets, silently ignore the failure.
                return 0;
            }
        }

        if len != SocketSize::SIZEOF_TCPINFO {
            return 0;
        }

        return info.State as u32;
    }

    fn Type(&self) -> (i32, i32, i32) {
        return (self.family, self.stype, -1)
    }
}



