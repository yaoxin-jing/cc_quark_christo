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

use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;
use super::mutex::*;
use core::ops::Deref;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use core::sync::atomic::AtomicU64;
use alloc::string::String;
use cache_padded::CachePadded;

use super::vcpu_mgr::*;

#[derive(Debug, Copy, Clone, Default)]
pub struct TaskId {
    pub data: u64
}

impl TaskId {
    #[inline]
    pub const fn New(addr: u64) -> Self {
        return Self {
            data: addr
        }
    }

    #[inline]
    pub fn Addr(&self) -> u64 {
        return self.data;
    }

    #[inline]
    pub fn Context(&self) -> &'static mut Context {
        unsafe {
            return &mut *(self.data as * mut Context)
        }
    }

    #[inline]
    pub fn Queue(&self) -> u64 {
        return self.Context().queueId.load(Ordering::Relaxed) as u64;
    }
}

#[derive(Debug, Default)]
pub struct TaskListIntern {
    pub head: u64,
    pub tail: u64,
    pub count: usize,
}

impl TaskListIntern {
    pub fn Enq(&mut self, taskId: TaskId) {
        let currContext = taskId.Context();
        if self.count == 0 {
            self.head = taskId.data;
            self.tail = taskId.data;
        } else {
            currContext.prev = self.tail;
            let mut tailContext = TaskId::New(self.tail).Context();
            tailContext.next = taskId.data;
            self.tail = taskId.data;
        }

        assert!(currContext.TaskState() == TaskState::Waiting ||
            currContext.TaskState() == TaskState::Running, // the task is still running
            "current state is {:?}", currContext.state);
        currContext.SetTaskState(TaskState::Ready);

        self.count += 1;
    }

    pub fn Remove(&mut self, taskId: TaskId) {
        let context = taskId.Context();
        assert!(context.TaskState() == TaskState::Ready, "current state is {:?}", context.state);

        let prev = context.prev;
        let next = context.next;

        if prev == 0 {
            self.head = next;
        } else {
            let prevContext = TaskId::New(prev).Context();
            prevContext.next = next;
        }

        if next == 0 {
            self.tail = prev;
        } else {
            let nextContext = TaskId::New(next).Context();
            nextContext.prev = prev;
        }

        self.count -= 1;

        context.prev = 0;
        context.next = 0;
        context.SetTaskState(TaskState::Running);
    }

    pub fn Deq(&mut self) -> Option<TaskId> {
        let mut curr = self.head;

        while curr != 0 {
            let taskId = TaskId::New(curr);
            let currentContext = taskId.Context();
            if currentContext.ready.load(Ordering::SeqCst) == 1 {
                self.Remove(taskId);
                return Some(taskId)
            }

            curr = currentContext.next;
        }

        return None
    }
}

#[derive(Debug, Default)]
pub struct TaskList(pub QMutex<TaskListIntern>);

impl Deref for TaskList {
    type Target = QMutex<TaskListIntern>;

    fn deref(&self) -> &QMutex<TaskListIntern> {
        &self.0
    }
}

impl TaskList {
    pub fn Dequeue(&self) -> Option<TaskId> {
        return self.lock().Deq();
    }

    pub fn Enqueue(&self, task: TaskId) {
        self.lock().Enq(task);
    }

    pub fn Len(&self) -> u64 {
        return self.lock().count as u64;
    }

    //return whether the remove task succeed, i.e. after lock, whether the task is in ready state
    pub fn Remove(&self, taskId: TaskId) -> bool {
        let context = taskId.Context();
        let mut t = self.lock();
        if context.TaskState() != TaskState::Ready {
            return false
        }

        t.Remove(taskId);
        return true;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    Running,
    Ready,
    Waiting,
}

impl Default for TaskState {
    fn default() -> Self {
        return Self::Ready
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct Context {
    pub rsp: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rdi: u64,

    pub ready: AtomicU64,
    pub fs: u64,
    //pub X86fpstate: Box<X86fpstate>,
    //pub sigFPState: Vec<Box<X86fpstate>>,
    // job queue id
    pub queueId: AtomicUsize,
    pub prev: u64,
    pub next: u64,
    pub state: QMutex<TaskState>
}

impl Context {
    pub fn New() -> Self {
        return Self {
            rsp: 0,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rdi: 0,

            ready: AtomicU64::new(1),

            fs: 0,
            //X86fpstate: Default::default(),
            //sigFPState: Default::default(),
            queueId: AtomicUsize::new(0),
            prev: 0,
            next: 0,
            state: QMutex::new(TaskState::Waiting)

        }
    }

    pub fn Ready(&self) -> u64 {
        return self.ready.load(Ordering::Acquire)
    }

    pub fn SetReady(&self, val: u64) {
        return self.ready.store(val, Ordering::SeqCst)
    }

    pub fn TaskId(&self) -> TaskId {
        return TaskId {
            data: self as * const _ as u64
        }
    }

    pub fn TaskState(&self) -> TaskState {
        return *self.state.lock()
    }

    pub fn SetTaskState(&self, taskState: TaskState) {
        *self.state.lock() = taskState;
    }

    // set the task state to waiting
    // return:  true if the current state is Running, i.e. normal state
    //          false if the current state is Ready, i.e. the io operation has finished
    pub fn SetWaiting(&self) -> bool {
        let mut state = self.state.lock();
        if *state == TaskState::Running {
            *state = TaskState::Waiting;
            return true;
        }

        assert!(*state == TaskState::Ready);
        return false;
    }
}

#[derive(Default)]
#[repr(C)]
#[repr(align(128))]
pub struct Scheduler {
    pub taskLists: Vec<CachePadded<TaskList>>,
    pub vcpuCnt: usize,
    pub taskCnt: AtomicUsize,
    pub readyTaskCnt: AtomicUsize,
    pub haltVcpuCnt: AtomicUsize,

    pub vcpuWaitMask: AtomicU64,
    pub VcpuArr : Vec<CPULocal>,
}

impl Scheduler {
    pub fn New(vcpuCount: usize) -> Self {
        let mut vcpuArr : Vec<CPULocal> = Vec::with_capacity(vcpuCount);
        let mut tasklists : Vec<CachePadded<TaskList>> = Vec::with_capacity(vcpuCount);
        for _i in 0..vcpuCount {
            vcpuArr.push(CPULocal::default());
            tasklists.push(CachePadded::new(TaskList::default()));
        }

        return Self {
            VcpuArr: vcpuArr,
            taskLists: tasklists,
            vcpuCnt: vcpuCount,
            ..Default::default()
        }
    }

    pub fn DecreaseHaltVcpuCnt(&self) {
        self.haltVcpuCnt.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn IncreaseHaltVcpuCnt(&self) -> usize {
        return self.haltVcpuCnt.fetch_add(1, Ordering::SeqCst);
    }

    pub fn HaltVcpuCnt(&self) -> usize {
        return self.haltVcpuCnt.load(Ordering::Acquire);
    }

    #[inline(always)]
    pub fn GlobalReadyTaskCnt(&self) -> usize {
        self.readyTaskCnt.load(Ordering::Acquire)
    }

    pub fn ReadyTaskCnt(&self, vcpuId: usize) -> u64 {
        return self.taskLists[vcpuId].Len();
    }

    #[inline(always)]
    pub fn IncReadyTaskCount(&self) -> usize {
        let cnt = self.readyTaskCnt.fetch_add(1, Ordering::SeqCst) + 1;
        return cnt
    }

    #[inline(always)]
    pub fn DecReadyTaskCount(&self) -> usize {
        let cnt = self.readyTaskCnt.fetch_sub(1, Ordering::SeqCst) - 1;
        return cnt;
    }

    pub fn ScheduleQ(&self, task: TaskId, vcpuId: u64) {
        //error!("ScheduleQ task {:x?} vcpu {}", task, vcpuId);
        let _cnt = {
            let mut list = self.taskLists[vcpuId as usize].lock();
            list.Enq(task);
            self.IncReadyTaskCount()
        };

        if vcpuId == 0 {
            self.WakeOne();
            return
        }

        let state = self.VcpuArr[vcpuId as usize].State();
        if state == VcpuState::Waiting {
            //error!("ScheduleQ: vcpu {} is waiting ..., wake it up", vcpuId);
            self.VcpuArr[vcpuId as usize].Wakeup();
        } else if state == VcpuState::Running {
            self.WakeOne();
        }
    }

    pub fn WakeOne(&self) -> i64 {
        loop {
            let mask = self.vcpuWaitMask.load(Ordering::Acquire);

            let vcpuId = mask.trailing_zeros() as usize;
            if vcpuId >= 64 {
                return -1;
            }

            if self.WakeIdleCPU(vcpuId) {
                return vcpuId as i64
            }
        }
    }

    pub fn WakeAll(&self) {
        for i in 1..self.vcpuCnt {
            self.WakeIdleCPU(i);
        }
    }

    pub fn WakeIdleCPU(&self, vcpuId: usize) -> bool {
        let vcpuMask = (1<<vcpuId) as u64;
        let prev = self.vcpuWaitMask.fetch_and(!vcpuMask, Ordering::Acquire);

        let wake = (prev & vcpuMask) != 0;
        if wake {
            self.VcpuArr[vcpuId].Wakeup();
        }

        return wake;
    }
}


pub struct TaskQueue(pub QMutex<VecDeque<TaskId>>);

impl Deref for TaskQueue {
    type Target = QMutex<VecDeque<TaskId>>;

    fn deref(&self) -> &QMutex<VecDeque<TaskId>> {
        &self.0
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        return Self::New();
    }
}

impl TaskQueue {
    pub fn New() -> Self {
        return TaskQueue(QMutex::new(VecDeque::with_capacity(128)));
    }

    pub fn Dequeue(&self) -> Option<TaskId> {
        return self.lock().pop_front();
    }

    pub fn Enqueue(&self, task: TaskId) {
        self.lock().push_back(task);
    }

    pub fn ToString(&self) -> String {
        return format!("{:x?} ", self.lock());
    }

    pub fn Len(&self) -> u64 {
        return self.lock().len() as u64;
    }
}
