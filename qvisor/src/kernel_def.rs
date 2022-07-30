use cache_padded::CachePadded;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use libc::*;
use std::fmt;

use super::qlib::kernel::kernel::waiter::EventMaskFromLinux;
use super::qlib::kernel::quring::uring_async::UringAsyncMgr;
use super::qlib::common::*;
use super::qlib::control_msg::*;
use super::qlib::kernel::memmgr::pma::*;
use super::qlib::kernel::task::*;
use super::qlib::kernel::Kernel::*;
use super::qlib::kernel::Tsc;
use super::qlib::kernel::TSC;
use super::qlib::kernel::socket::hostinet::asyncsocket::*;
use super::qlib::linux::time::*;
use super::qlib::linux_def::*;
use super::qlib::loader::*;
use super::qlib::mutex::*;
use super::qlib::perf_tunning::*;
use super::qlib::qmsg::*;
use super::qlib::rdma_svc_cli::*;
use super::qlib::task_mgr::*;
use super::qlib::vcpu_mgr::*;
use super::qlib::socket_buf::*;
use super::qlib::*;
use super::ThreadId;
use super::FD_NOTIFIER;
use super::QUARK_CONFIG;
use super::URING_MGR;
use super::VMS;
use super::vmspace::VMSpace;
use crate::SHARE_SPACE;

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SuperError is here!")
    }
}

impl<'a> ShareSpace {
    pub fn AQCall(&self, msg: &HostOutputMsg) {
        panic!("ShareSpace::AQCall {:x?}", msg);
    }

    pub fn Schedule(&self, _taskId: u64) {}
}

impl<'a> ShareSpace {
    pub fn LogFlush(&self, partial: bool) {
        let lock = self.logLock.try_lock();
        if lock.is_none() {
            return;
        }

        let logfd = self.logfd.load(Ordering::Relaxed);

        let mut cnt = 0;
        if partial {
            let (addr, len) = self.ConsumeAndGetAvailableWriteBuf(cnt);
            if len == 0 {
                return;
            }

            /*if len > 16 * 1024 {
                len = 16 * 1024
            };*/

            let ret = unsafe { libc::write(logfd, addr as _, len) };
            if ret < 0 {
                panic!("log flush fail {}", ret);
            }

            if ret < 0 {
                panic!("log flush fail {}", ret);
            }

            cnt = ret as usize;
            self.ConsumeAndGetAvailableWriteBuf(cnt);
            return;
        }

        loop {
            let (addr, len) = self.ConsumeAndGetAvailableWriteBuf(cnt);
            if len == 0 {
                return;
            }

            let ret = unsafe { libc::write(logfd, addr as _, len) };
            if ret < 0 {
                panic!("log flush fail {}", ret);
            }

            cnt = ret as usize;
        }
    }
}

impl ShareSpace {
    pub fn Init(&mut self, vcpuCount: usize, controlSock: i32, rdmaSvcCliSock: i32, podId: [u8; 64]) {
        *self.config.write() = *QUARK_CONFIG.lock();
        let mut values = Vec::with_capacity(vcpuCount);
        for _i in 0..vcpuCount {
            values.push([AtomicU64::new(0), AtomicU64::new(0)])
        }

        if self.config.read().EnableRDMA {
            self.rdmaSvcCli = CachePadded::new(RDMASvcClient::initialize(
                rdmaSvcCliSock,
                MemoryDef::RDMA_LOCAL_SHARE_OFFSET,
                MemoryDef::RDMA_GLOBAL_SHARE_OFFSET,
                podId,
            ));
        }

        let SyncLog = self.config.read().SyncPrint();
        if !SyncLog {
            let bs = super::qlib::bytestream::ByteStream::Init(128 * 1024); // 128 MB
            *self.logBuf.lock() = Some(bs);
        }

        self.scheduler = Scheduler::New(vcpuCount);
        self.values = values;

        self.scheduler.Init();
        self.SetLogfd(super::print::LOG.Logfd());
        self.hostEpollfd
            .store(FD_NOTIFIER.Epollfd(), Ordering::SeqCst);
        self.controlSock = controlSock;
        self.supportMemoryBarrier = VMS.lock().haveMembarrierGlobal;
        super::vmspace::VMSpace::BlockFd(controlSock);
    }

    pub fn TlbShootdown(&self, vcpuMask: u64) -> u64 {
        let vcpu_len = self.scheduler.VcpuArr.len();
        for i in 1..vcpu_len {
            if ((1 << i) & vcpuMask != 0)
                && SHARE_SPACE.scheduler.VcpuArr[i].GetMode() == VcpuMode::User
            {
                let cpu = VMS.lock().vcpus[i].clone();
                SHARE_SPACE.scheduler.VcpuArr[i].InterruptTlbShootdown();
                cpu.interrupt();
            }
        }
        return 0;
    }

    pub fn Yield() {
        use std::{thread, time};
        let dur = time::Duration::new(0, 1000);
        thread::sleep(dur);
    }

    pub fn CheckVcpuTimeout(&self) {
        let now = TSC.Rdtsc();
        for i in 1..self.scheduler.VcpuArr.len() {
            let enterAppTimestamp = self.scheduler.VcpuArr[i].EnterAppTimestamp();
            if enterAppTimestamp == 0 {
                continue;
            }

            //error!("CheckVcpuTimeout {}/{}/{}/{}", i, enterAppTimestamp, now, Tsc::Scale(now - enterAppTimestamp));
            if Tsc::Scale(now - enterAppTimestamp) * 1000 > 2 * CLOCK_TICK {
                //self.scheduler.VcpuArr[i].ResetEnterAppTimestamp();

                // retry to send signal for each 2 ms
                self.scheduler.VcpuArr[i].SetEnterAppTimestamp(enterAppTimestamp + CLOCK_TICK / 5);
                self.scheduler.VcpuArr[i].InterruptThreadTimeout();
                //error!("CheckVcpuTimeout {}/{}/{}/{}", i, enterAppTimestamp, now, Tsc::Scale(now - enterAppTimestamp));
                let vcpu = VMS.lock().vcpus[i].clone();
                vcpu.interrupt();
            }
        }
    }
}

impl<T: ?Sized> QMutexIntern<T> {
    pub fn GetID() -> u64 {
        return super::ThreadId() as u64;
    }
}

#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfType {
    Start,
    Other,
    QCall,
    AQCall,
    AQHostCall,
    BusyWait,
    IdleWait,
    BufWrite,
    End,
    User, //work around for kernel clone
    Idle, //work around for kernel clone

    ////////////////////////////////////////
    Blocked,
    Kernel,
}

impl CounterSet {
    pub const PERM_COUNTER_SET_SIZE: usize = 1;
    pub fn GetPerfId(&self) -> usize {
        0
    }

    pub fn PerfType(&self) -> &str {
        return "PerfPrint::Host";
    }
}

pub fn switch(_from: TaskId, _to: TaskId) {}

pub fn OpenAt(_task: &Task, _dirFd: i32, _addr: u64, _flags: u32) -> Result<i32> {
    return Ok(0);
}

pub fn SignalProcess(_signalArgs: &SignalArgs) {}

pub fn StartRootContainer(_para: *const u8) {}
pub fn StartExecProcess(_fd: i32, _process: Process) {}
pub fn StartSubContainerProcess(_elfEntry: u64, _userStackAddr: u64, _kernelStackAddr: u64) {}

pub unsafe fn CopyPageUnsafe(_to: u64, _from: u64) {}

impl CPULocal {
    pub fn CpuId() -> usize {
        return ThreadId() as _;
    }

    pub fn Wakeup(&self) {
        let val: u64 = 8;
        let ret = unsafe { libc::write(self.eventfd, &val as *const _ as *const libc::c_void, 8) };
        if ret < 0 {
            panic!("KIOThread::Wakeup fail...");
        }
    }
}

impl PageMgr {
    pub fn CopyVsysCallPages(&self, _addr: u64) {}
}

pub fn ClockGetTime(clockId: i32) -> i64 {
    let ts = Timespec::default();
    let res = unsafe {
        clock_gettime(
            clockId as clockid_t,
            &ts as *const _ as u64 as *mut timespec,
        ) as i64
    };

    if res == -1 {
        return errno::errno().0 as i64;
    } else {
        return ts.ToNs().unwrap();
    }
}

pub fn VcpuFreq() -> i64 {
    return VMS.lock().GetVcpuFreq();
}

pub fn NewSocket(fd: i32) -> i64 {
    return VMSpace::NewSocket(fd);
}

pub fn UringWake(minCompleted: u64) {
    URING_MGR
        .lock()
        .Wake(minCompleted as _)
        .expect("qlib::HYPER CALL_URING_WAKE fail");
}

impl HostSpace {
    pub fn Close(fd: i32) -> i64 {
        return VMSpace::Close(fd);
    }

    pub fn Call(msg: &mut Msg, _mustAsync: bool) -> u64 {
        panic!("HostSpace::Call msg {:x?}", msg);
    }

    pub fn HCall(msg: &mut Msg, _lock: bool) -> u64 {
        panic!("HostSpace::HCall msg {:x?}", msg);
    }
}

#[inline]
pub fn child_clone(_userSp: u64) {}

pub fn InitX86FPState(_data: u64, _useXsave: bool) {}

#[inline]
pub fn VcpuId() -> usize {
    return ThreadId() as usize;
}

pub fn HugepageDontNeed(addr: u64) {
    let ret = unsafe {
        libc::madvise(
            addr as _,
            MemoryDef::HUGE_PAGE_SIZE as usize,
            MAdviseOp::MADV_DONTNEED,
        )
    };
    assert!(ret == 0, "HugepageDontNeed::Host fail with {}", ret)
}

impl UringAsyncMgr {
    pub fn FreeSlot(&self, id: usize) {
        self.freeids.lock().push_back(id as _);
    }
}

impl AsyncSocketOperations {
    pub fn GetRet(ret: i64) -> i64 {
        if ret == -1 {
            //info!("get error, errno is {}", errno::errno().0);
            return -errno::errno().0 as i64;
        }

        return ret;
    }

    pub fn IOAccept(&self) -> Result<AcceptItem> {
        let mut ai = AcceptItem::default();
        ai.len = ai.addr.data.len() as _;
        let res = VMSpace::IOAccept(
            self.fd,
            &ai.addr as *const _ as u64,
            &ai.len as *const _ as u64,
        ) as i32;
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        ai.fd = res;
        return Ok(ai);
    }


    pub fn Notify(&self, mask: EventMask) {
        let state = self.SocketBufState();
        let queue = self.queue.clone();
        match state {
            SockState::TCPInit => {
                //panic!("AsyncSocketOperations::Notify expect state TCPInit {:x}", mask);
            }
            SockState::TCPConnecting => {
                /*assert!(mask & (EVENT_OUT | EVENT_ERR | EVENT_HUP) != 0, "AsyncSocketOperations::Notify expect state TCPConnecting {:x}", mask);
                // connecting moving to connected
                let mut val: i32 = 0;
                let len: i32 = 4;
                let res = HostSpace::GetSockOpt(
                    self.fd,
                    LibcConst::SOL_SOCKET as i32,
                    LibcConst::SO_ERROR as i32,
                    &mut val as *mut i32 as u64,
                    &len as *const i32 as u64,
                ) as i32;

                if res < 0 {
                    return Err(Error::SysError(-res));
                }

                if val != 0 {
                    if val == SysErr::ECONNREFUSED {
                        return Err(Error::SysError(SysErr::EINPROGRESS));
                    }
                    return Err(Error::SysError(val as i32));
                }

                self.SetRemoteAddr(socketaddr.to_vec())?;
                let socketBuf = Arc::new(SocketBuff::Init(MemoryDef::DEFAULT_BUF_PAGE_COUNT));
                *self.state.lock() = SockState::TCPData(socketBuf);*/
                error!("SockState::TCPConnecting is not async");
                queue.Notify(EventMaskFromLinux(mask as u32));
            }
            SockState::TCPServer(acceptQueue) => {
                assert!(mask & (EVENT_IN | EVENT_ERR | EVENT_HUP)!= 0, "AsyncSocketOperations::Notify expect state TCPServer {:x}", mask);
                loop {
                    let ai = match self.IOAccept() {
                        Err(Error::SysError(SysErr::EAGAIN)) => {
                            break;
                        }
                        Err(Error::SysError(syserr)) => {
                            acceptQueue.lock().SetErr(syserr);
                            queue.Notify(EventMaskFromLinux((EVENT_ERR | READABLE_EVENT) as u32));
                            break;
                        }
                        Ok(ai) => ai,
                        _ => {
                            panic!("impossible!");
                        }
                    };

                    let (trigger, hasSpace) = acceptQueue.lock().Enq(ai);
                    if trigger {
                        self.queue.Notify(EventMaskFromLinux(READABLE_EVENT as u32));
                    }

                    if !hasSpace {
                        break;
                    }
                }
            }

            SockState::TCPData(buf) => {
                assert!(mask & (EVENT_IN | EVENT_OUT | EVENT_ERR | EVENT_HUP)!= 0, "AsyncSocketOperations::Notify expect state TCPData {:x}", mask);

                let fd = self.fd;
                if mask & EVENT_OUT != 0 {
                    let (mut addr, mut len) = buf.GetAvailableWriteBuf();
                    while addr > 0 {
                        let ret = unsafe {
                            libc::write(fd, addr as _, len as _)
                        };

                        let result = if ret < 0 {
                            Self::GetRet(ret as i64) as i32
                        } else {
                            ret as i32
                        };

                        if result < 0 {
                            if result == -SysErr::EAGAIN {
                                break;
                            }
                            buf.SetErr(-result);
                            queue.Notify(EventMaskFromLinux((EVENT_ERR | READABLE_EVENT) as u32));
                            return;
                            //return true;
                        }

                        // EOF
                        // to debug
                        if result == 0 {
                            buf.SetWClosed();
                            if buf.ProduceReadBuf(0) {
                                queue.Notify(EventMaskFromLinux(WRITEABLE_EVENT as u32));
                            } else {
                                queue.Notify(EventMaskFromLinux(WRITEABLE_EVENT as u32));
                            }
                            return;
                        }

                        let (trigger, taddr, tlen) = buf.ConsumeAndGetAvailableWriteBuf(result as usize);
                        if trigger {
                            queue.Notify(EventMaskFromLinux(WRITEABLE_EVENT as u32));
                        }

                        addr = taddr;
                        len = tlen;
                    }

                    if buf.PendingWriteShutdown() {
                        queue.Notify(EVENT_PENDING_SHUTDOWN);
                    }
                }

                if mask & EVENT_IN != 0 {
                    let (mut addr, mut len) = buf.GetFreeReadBuf();
                    while addr > 0 {
                        let ret = unsafe {
                            libc::read(fd, addr as _, len as _) as i32
                        };

                        let result = if ret < 0 {
                            Self::GetRet(ret as i64) as i32
                        } else {
                            ret as i32
                        };

                        if result < 0 {
                            if result == -SysErr::EAGAIN {
                                break;
                            }
                            buf.SetErr(-result);
                            queue
                                .Notify(EventMaskFromLinux((EVENT_ERR | READABLE_EVENT) as u32));
                            return;
                        }

                        if result == 0 {
                            buf.SetRClosed();
                            if buf.HasReadData() {
                                queue.Notify(EventMaskFromLinux(READABLE_EVENT as u32));
                            } else {
                                queue.Notify(EventMaskFromLinux(EVENT_HUP as u32));
                            }
                            return;
                        }

                        let (trigger, taddr, tlen) = buf.ProduceAndGetFreeReadBuf(result as usize);
                        if trigger {
                            queue.Notify(EventMaskFromLinux(READABLE_EVENT as u32));
                        }

                        addr = taddr;
                        len = tlen;
                    }
                }

                if mask & (EVENT_ERR | EVENT_HUP) != 0 {
                    let result = unsafe {
                        libc::read(fd, 0 as _, 0 as _) as i32
                    };

                    if result < 0 {
                        buf.SetErr(-result);
                        queue
                            .Notify(EventMaskFromLinux((EVENT_ERR | READABLE_EVENT) as u32));
                    }

                    if result == 0 {
                        buf.SetRClosed();
                        if buf.HasReadData() {
                            queue.Notify(EventMaskFromLinux(READABLE_EVENT as u32));
                        } else {
                            queue.Notify(EventMaskFromLinux(EVENT_HUP as u32));
                        }
                    }
                }
            }
        }
    }
}