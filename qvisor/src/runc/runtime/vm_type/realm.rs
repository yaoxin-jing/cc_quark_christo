// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,x
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::Deref;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use hashbrown::HashMap;
use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VmFd, Cap, DeviceFd};

use crate::arch::VirtCpu;
use crate::arch::vm::tee::kvm;
use crate::arch::vm::vcpu::ArchVirtCpu;
use crate::print::LOG;
use crate::qlib::ShareSpace;
use crate::qlib::addr::{PageOpts, Addr};
use crate::qlib::kernel::SHARESPACE;
use crate::qlib::kernel::kernel::{futex, timer};
use crate::qlib::kernel::vcpu::CPU_LOCAL;
use crate::qlib::pagetable::{self, PageTableFlags};
use crate::qlib::pagetable::PageTables;
use crate::runc::runtime::vm_type::resources::MemArea;
use crate::vmspace::VMSpace;
use crate::vmspace::tsot_agent::TSOT_AGENT;
use crate::{ROOT_CONTAINER_ID, QUARK_CONFIG, URING_MGR, VMS, PMA_KEEPER, SHARE_SPACE, KERNEL_IO_THREAD};
use crate::runc::runtime::loader::Args;
use crate::{qlib::{config::CCMode, kernel::Kernel::{ENABLE_CC, IDENTICAL_MAPPING},
            linux_def::MemoryDef}, runc::runtime::{vm_type::resources::{MemAreaType,
            MemLayoutConfig}, vm::{VirtualMachine, self}}, arch::tee::util::{adjust_addr_to_host,
            adjust_addr_to_guest}, elf_loader::KernelELF};
use super::{resources::VmResources, VmType};
use crate::qlib::common::Error;

use crate::arch::vm::tee::kvm::{KvmCapArmRmeMeasurementAlgo, KVM_VM_TYPE_ARM_IPA_SIZE_DEFAULT,
    KVM_VM_TYPE_ARM_RPV_SIZE_BYTE};

/// Values are arbitrary, suggested by another demo project.
#[derive(Debug)]
pub struct vGic3 {
    pub size: u64,
    pub distributor_base: u64,
    pub redistributor_base: u64,
    pub its_base: u64,
    pub irq_lines: u64,
    pub vgic_fd: Option<DeviceFd>,
    pub its_fd: Option<DeviceFd>,
}

#[derive(Debug)]
struct Sve {
    version: u32,
    vector_length: u32,
}

impl Default for Sve {
    fn default() -> Self {
        Self {
            version: 2,
            vector_length: 128,
        }
    }
}

impl Default for vGic3 {
    fn default() -> Self {
       let _size = 0x2_0000;
       let _vgic_end = 0x200_0000;
       let _dist_base = _vgic_end - _size;
       let _redist_base = _dist_base - _size;
       let _its_base = _redist_base - _size;
        Self {
            size: _size,
            distributor_base: _dist_base,
            redistributor_base: _redist_base,
            its_base: _its_base,
            irq_lines: 64,
            vgic_fd: None,
            its_fd: None,
        }
    }
}

#[derive(Debug)]
pub struct Realm {
    pub ipa_size: u64,
    rpv_token: [u8; 64],
    pub vgic3: vGic3,
    hash_algo: KvmCapArmRmeMeasurementAlgo,
    sve: Option<Sve>,
    vmid: u16,
}

impl Default for Realm {
    fn default() -> Self {
        Self {
            ipa_size: KVM_VM_TYPE_ARM_IPA_SIZE_DEFAULT,
            rpv_token: [0u8; KVM_VM_TYPE_ARM_RPV_SIZE_BYTE as usize],
            vgic3: vGic3::default(),
            sve: None,
            hash_algo: KvmCapArmRmeMeasurementAlgo::Sha256,
            vmid: 0,
        }
    }
}
impl Realm {
    pub fn vgic_init_finalize(&self) -> Result<(), Error> {
        kvm::kvm_arm_vgic_init_finalize(self.vgic3.vgic_fd.as_ref(), self.vgic3.irq_lines)
    }

    pub fn activate_realm(&self, vm_fd: &mut VmFd) -> Result<(), Error> {
        kvm::kvm_arm_rme_activate_realm(vm_fd)
    }
}

#[derive(Debug)]
pub struct VmCcRealm {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
    cc_mode: CCMode,
    realm: Realm,
}

impl VmType for VmCcRealm {
    //NOTE: In the future we want to be able to customize the initialization through
    //      user provided configuration.
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error>
        where Self: Sized {
        ENABLE_CC.store(true, Ordering::Release);
        let _pod_id = args.expect("VM creation expects arguments").ID.clone();
        let default_min_vcpus = 1; //Preliminary functionality test
        let _emul_type: CCMode = CCMode::Realm;
        IDENTICAL_MAPPING.store(false, Ordering::Release);

        let mut _mem_map:HashMap<MemAreaType, MemArea> = HashMap::new();
        _mem_map.insert(
            MemAreaType::PrivateHeapArea,
            MemArea {
                base_host: adjust_addr_to_host(MemoryDef::GUEST_PRIVATE_HEAP_OFFSET, _emul_type),
                base_guest: MemoryDef::GUEST_PRIVATE_HEAP_OFFSET,
                size: MemoryDef::GUEST_PRIVATE_HEAP_SIZE,
                guest_private: true,
                host_backedup: true });
        _mem_map.insert(
            MemAreaType::KernelArea,
            MemArea {
                base_host: adjust_addr_to_host(MemoryDef::PHY_LOWER_ADDR, _emul_type),
                base_guest: MemoryDef::PHY_LOWER_ADDR,
                size: MemoryDef::FILE_MAP_OFFSET - MemoryDef::PHY_LOWER_ADDR,
                guest_private: true,
                host_backedup: true });
        _mem_map.insert(
            MemAreaType::FileMapArea,
            MemArea {
                base_host: MemoryDef::FILE_MAP_OFFSET,
                base_guest: MemoryDef::FILE_MAP_OFFSET,
                size: MemoryDef::FILE_MAP_SIZE,
                guest_private: false,
                host_backedup: true });
        _mem_map.insert(
            MemAreaType::SharedHeapArea,
            MemArea {
                base_host: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
                base_guest: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
                size: MemoryDef::GUEST_HOST_SHARED_HEAP_SIZE,
                guest_private: false,
                host_backedup: true });
        #[cfg(target_arch = "aarch64")] {
            _mem_map.insert(
                MemAreaType::HypercallMmioArea,
                MemArea {
                    base_host: u64::MAX,
                    base_guest: MemoryDef::HYPERCALL_MMIO_BASE,
                    size: MemoryDef::HYPERCALL_MMIO_SIZE,
                    guest_private: false, // Semantically this is shared
                    host_backedup: false });
        }
        let mem_layout_config = MemLayoutConfig {
            mem_area_map: _mem_map,
            kernel_stack_size: MemoryDef::DEFAULT_STACK_SIZE as usize,
            guest_mem_size: MemoryDef::KERNEL_MEM_INIT_REGION_SIZE * MemoryDef::ONE_GB,
        };
        let _kernel_bin_path = VirtualMachine::KERNEL_IMAGE.to_string();
        let _vdso_bin_path = VirtualMachine::VDSO_PATH.to_string();
        let _sbox_uid_name = vm::SANDBOX_UID_NAME.to_string();

        let mut elf = KernelELF::New().expect("Failed to create elf object.");
        let _kernel_entry = elf
            .LoadKernel(_kernel_bin_path.as_str())
            .expect("Failed to load kernel from given path.");
        elf.LoadVDSO(_vdso_bin_path.as_str())
            .expect("Failed to load vdso from given path.");
        let _vdso_address = adjust_addr_to_guest(elf.vdsoStart, _emul_type);
        //TODO: Customize realm fields
        let mut _realm = Realm::default();
        let vm_realm = Self {
            vm_resources: VmResources {
                min_vcpu_amount: default_min_vcpus,
                kernel_bin_path: _kernel_bin_path,
                vdso_bin_path: _vdso_bin_path,
                sandbox_uid_name: _sbox_uid_name,
                pod_id: _pod_id,
                mem_layout: mem_layout_config,
            },
            entry_address: _kernel_entry,
            vdso_address: _vdso_address,
            cc_mode: _emul_type,
            realm: _realm,
        };
        let box_type: Box<dyn VmType> = Box::new(vm_realm);

        Ok((box_type, elf))
    }

    fn create_vm(mut self: Box<Self>, kernel_elf: KernelELF, args: crate::runc::runtime::loader::Args)
        -> Result<VirtualMachine, Error> {
        crate::GLOBAL_ALLOCATOR.InitPrivateAllocator();
        *ROOT_CONTAINER_ID.lock() = args.ID.clone();
        if QUARK_CONFIG.lock().PerSandboxLog {
            let sandbox_name = match args
                .Spec
                .annotations
                .get(self.vm_resources.sandbox_uid_name.as_str())
            {
                None => args.ID[0..12].to_owned(),
                Some(name) => name.clone(),
            };
            LOG.Reset(&sandbox_name);
        }

        let cpu_count = args.GetCpuCount();
        let reserve_cpu_count = QUARK_CONFIG.lock().ReserveCpuCount;
        let cpu_count = if cpu_count == 0 {
            VMSpace::VCPUCount() - reserve_cpu_count
        } else {
            cpu_count.min(VMSpace::VCPUCount() - reserve_cpu_count)
        };

        if let Err(e) = self.vm_space_initialize(cpu_count, args) {
            error!("VM creation failed on VM-Space initialization.");
            return Err(e);
        } else {
            info!("VM creation - VM-Space initialization finished.");
        }

        {
            URING_MGR.lock();
        }

        let mut _kvm: Kvm;
        let mut vm_fd: VmFd;
        let _kvm_fd = VMS.lock().args.as_ref().unwrap().KvmFd;
        match self.create_kvm_vm(_kvm_fd) {
            Ok((__kvm, __vm_fd)) => {
                _kvm = __kvm;
                vm_fd = __vm_fd;
                info!("VM cration - kvm-vm_fd initialized.");
            }
            Err(e) => {
                error!("VM creation failed on kvm-vm creation.");
                return Err(e);
            }
        };

        self.vm_memory_initialize(&vm_fd)
            .expect("VM creation failed on memory initialization.");
        self.post_memory_initialize(&vm_fd)
            .expect("VM post memory initialization failed");
        let (_, pheap, _) = self.vm_resources.mem_area_info(MemAreaType::PrivateHeapArea).unwrap();
        let _vcpu_total = VMS.lock().vcpuCount;
        let _auto_start = VMS.lock().args.as_ref().unwrap().AutoStart;
        let _vcpus = self
            .vm_vcpu_initialize(
                &_kvm,
                &vm_fd,
                _vcpu_total,
                self.entry_address,
                _auto_start,
                Some(pheap),
                None)
            .expect("VM creation failed on vcpu creation.");

        self.as_mut().post_vm_initialize(&mut vm_fd)?;
        let _vm_type: Box<dyn VmType> = self;
        let vm = VirtualMachine {
            kvm: _kvm,
            vmfd: vm_fd,
            vm_type: _vm_type,
            vcpus: _vcpus,
            elf: kernel_elf,
        };

        Ok(vm)
    }

    fn vm_space_initialize(&self, vcpu_count: usize, args: crate::runc::runtime::loader::Args) -> Result<(), crate::qlib::common::Error> {
        let vms = &mut VMS.lock();
        vms.vcpuCount = vcpu_count.max(self.vm_resources.min_vcpu_amount);
        vms.cpuAffinit = true;
        vms.RandomVcpuMapping();
        vms.controlSock = args.ControlSock;
        vms.vdsoAddr = self.vdso_address;
        vms.pivot = args.Pivot;
        if let Some(id) = args
            .Spec
            .annotations
            .get(self.vm_resources.sandbox_uid_name.as_str())
        {
            vms.podUid = id.clone();
        } else {
            info!("No sandbox id found in specification.");
        }

        let (fmap_base_host, _, fmap_size) = self.vm_resources
            .mem_area_info(MemAreaType::FileMapArea).unwrap();
        PMA_KEEPER.Init(fmap_base_host, fmap_size);
        PMA_KEEPER.InitHugePages();
        vms.pageTables = PageTables::New(&vms.allocator)?;

        //TODO: Break the mapping here or in kernel:
        //      Adjust to Shared/NotShared bit
        //todo!("Kernel Pt kreation");

        let untrusted_range = PageTableFlags::new_with_bit_set(&self.realm.ipa_size - 1);
        let block_size = pagetable::HugePageType::MB2;
        for (_mt, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            info!("VM: Creating mapping for {}", _mt.to_string());
            if *_mt == MemAreaType::HypercallMmioArea {
                 let mut page_opt = PageOpts::Zero();
                 page_opt.SetWrite().SetGlobal().SetPresent().SetAccessed().SetMMIOPage();
                 vms.KernelMap(Addr(_ma.base_guest), Addr(_ma.base_guest + _ma.size),
                     Addr(_ma.base_guest), page_opt.Val())?;
            } else {
                let mut entry_opt = PageOpts::Zero();
                entry_opt = PageOpts::Kernel();
                entry_opt.SetBlock();

                if _ma.guest_private == false {
                    entry_opt.set_option_x(&untrusted_range);
                }

                if vms.KernelMapHugeTable(Addr(_ma.base_guest), Addr(_ma.base_guest + _ma.size),
                    Addr(_ma.base_guest), entry_opt.Val(), block_size).unwrap() == false {
                        panic!("VM: Failed to map {}", _mt.to_string());
                }
            }
        }
        vms.args = Some(args);

        Ok(())
    }

    fn init_share_space(vcpu_count: usize, control_sock: i32, rdma_svc_cli_sock: i32,
                     pod_id: [u8; 64], share_space_addr: Option<u64>,
                     has_global_mem_barrier: Option<bool>) -> Result<(), crate::qlib::common::Error>
        where Self: Sized {
        use core::sync::atomic;
        crate::GLOBAL_ALLOCATOR.vmLaunched.store(true, atomic::Ordering::SeqCst);
        let shared_space_obj = unsafe {
            &mut *(share_space_addr.expect("Failed to initialize shared space in host\
                            - shared-space-table address is missing") as *mut ShareSpace)
        };
        let default_share_space_table = ShareSpace::New();
        let def_sh_space_tab_size = core::mem::size_of_val(&default_share_space_table);
        let sh_space_obj_size = core::mem::size_of_val(shared_space_obj);
        assert!(sh_space_obj_size == def_sh_space_tab_size,
            "Guest passed shared-space address does not match to a shared-space object.\
                Expected obj size:{:#x} - found:{:#x}", def_sh_space_tab_size, sh_space_obj_size);
        unsafe {
            core::ptr::write(shared_space_obj as *mut ShareSpace, default_share_space_table);
        }

        {
            let mut vms = VMS.lock();
            let shared_copy = vms.args.as_ref().unwrap().Spec.Copy();
            vms.args.as_mut().unwrap().Spec = shared_copy;
        }

        shared_space_obj.Init(vcpu_count, control_sock, rdma_svc_cli_sock, pod_id);
        SHARE_SPACE.SetValue(share_space_addr.unwrap());
        SHARESPACE.SetValue(share_space_addr.unwrap());
        URING_MGR.lock().Addfd(crate::print::LOG.Logfd()).unwrap();
        let share_space_ptr = SHARE_SPACE.Ptr();
        URING_MGR.lock().Addfd(share_space_ptr.HostHostEpollfd()).unwrap();
        URING_MGR.lock().Addfd(control_sock).unwrap();
        KERNEL_IO_THREAD.Init(share_space_ptr.scheduler.VcpuArr[0].eventfd);
        unsafe {
            CPU_LOCAL.Init(&SHARESPACE.scheduler.VcpuArr);
            futex::InitSingleton();
            timer::InitSingleton();
        }

        if SHARESPACE.config.read().EnableTsot {
            TSOT_AGENT.NextReqId();
            SHARESPACE.dnsSvc.Init().unwrap();
        }
        crate::print::SetSyncPrint(share_space_ptr.config.read().SyncPrint());

        Ok(())
    }

    fn create_kvm_vm(&mut self, kvm_fd: i32) ->
        Result<(kvm_ioctls::Kvm, kvm_ioctls::VmFd), Error> {
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        if !kvm.check_extension(Cap::ImmediateExit) {
            panic!("Can not create VM - KVM_CAP_IMMEDIATE_EXIT is not supported.");
        }
        let supported_ipa_size = kvm.check_extension(Cap::ArmVmIPASize) as u64;
        if  supported_ipa_size < self.realm.ipa_size {
            panic!("Can not create VM - IPA_SIZE:{} exceeds host limit:{}",
                self.realm.ipa_size, supported_ipa_size);
        }
        let vm_type = kvm::KVM_VM_TYPE_ARM_REALM | kvm::kvm_vm_arm_ipa_size(self.realm.ipa_size);
        let vm_fd = kvm.create_vm_with_type(vm_type)
            .map_err(|e| Error::IOError(format!("Failed to crate a kvm-vm with error:{:?}", e)))?;

        self.configure_realm(&vm_fd);
        let (vgic_fd, its_fd): (DeviceFd, DeviceFd) = self.create_realm_dependency_devices(&vm_fd)
            .expect("Can not create VM - failed to create devices.");
        self.realm.vgic3.vgic_fd = Some(vgic_fd);
        self.realm.vgic3.its_fd = Some(its_fd);

        Ok((kvm, vm_fd))
    }

    fn vm_memory_initialize(&self, vm_fd: &kvm_ioctls::VmFd) -> Result<(), Error> {
        info!("VM creation: KVM guest memory initialization.");
        let mut _slot = 1;
        let mut kvm_mem_regions: Vec<kvm_userspace_memory_region> = Vec::new();
        for (_, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            if _ma.host_backedup {
                info!("MemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
                    _ma.base_guest, _ma.base_host, _ma.size >> 20);
                let _region = kvm_userspace_memory_region {
                    slot: _slot,
                    guest_phys_addr: _ma.base_guest,
                    memory_size: _ma.size,
                    userspace_addr: _ma.base_host,
                    flags: 0,
                };
                kvm_mem_regions.push(_region);
                _slot+=1;
            }
        }
        for region in kvm_mem_regions {
            unsafe {
                vm_fd.set_user_memory_region(region).map_err(|e| {
                    Error::IOError(format!("Failed to set kvm slot-memory region :{} - error:{:?}",
                        region.slot, e))})?;
            }
        }
        Ok(())
    }

    fn post_memory_initialize(&mut self, vm_fd: &VmFd) -> Result<(), Error> {
        info!("VM: Init Realm IPA.");
        for (_mt, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            if _ma.guest_private {
                info!("VM: Init IPA for region:{:?}",_mt.to_string());
                kvm::kvm_vm_arm_rme_init_ipa_range(&vm_fd, _ma.base_guest, _ma.size)
                    .expect("VM: Fialed to init IPA for region:{_mt.to_string():?}");
            }
        }
        info!("VM: Populate Realm memory.");
        for (_mt, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            if _ma.guest_private {
                info!("VM: Populate Realm with region:{:?}",_mt.to_string());
                kvm::kvm_vm_arm_rme_populate_range(&vm_fd, _ma.base_guest, _ma.size)
                    .expect("VM: Fialed to populate for region:{_mt.to_string():?}");
            }
        }
        Ok(())
    }

    fn vm_vcpu_initialize(&self, kvm: &kvm_ioctls::Kvm, vm_fd: &kvm_ioctls::VmFd, total_vcpus: usize, entry_addr: u64,
                        auto_start: bool, page_allocator_addr: Option<u64>,
                        share_space_addr: Option<u64>) -> Result<Vec<std::sync::Arc<crate::arch::vm::vcpu::ArchVirtCpu>>, crate::qlib::common::Error> {
        let mut vcpus: Vec<Arc<ArchVirtCpu>> = Vec::with_capacity(total_vcpus);

        for vcpu_id in 0..total_vcpus {
            let vcpu = Arc::new(ArchVirtCpu::new_vcpu(
                vcpu_id as usize,
                total_vcpus,
                &vm_fd,
                entry_addr,
                page_allocator_addr,
                share_space_addr,
                auto_start,
                self.vm_resources.mem_layout.kernel_stack_size,
                Some(&kvm),
                self.cc_mode)?);

            vcpus.push(vcpu);
        }

        for vcpu in &vcpus {
            vcpu.vcpu_init()?;
            vcpu.initialize_sys_registers()?;
            vcpu.initialize_cpu_registers()?;
        }

        VMS.lock().vcpus = vcpus.clone();

        Ok(vcpus)
    }

    fn post_vm_initialize(&mut self, vm_fd: &mut VmFd) -> Result<(), crate::qlib::common::Error> {
        self.realm.vgic_init_finalize()
            .expect("VM: Failed to finalize vGIC initialization.");
        let vms = VMS.lock();
        for vcpu in &vms.vcpus {
            let _ = vcpu.vcpu_init_finalize();
        }
        self.realm.activate_realm(vm_fd)
            .expect("VM: Failed to activate realm");

        Ok(())

    }

    fn post_init_upadate(&mut self) -> Result<(), crate::qlib::common::Error> {
        todo!()
    }
}

impl VmCcRealm {
    fn configure_realm(&self, vm_fd: &VmFd) {
        self.personalize_realm(&vm_fd)
            .expect("VM creation failed: can't personalize realm.");
        self.create_realm_descriptor(&vm_fd)
            .expect("VM creation failed: can't create realm descriptor.")
    }

    fn personalize_realm(&self, vm_fd: &VmFd) -> Result<(), Error> {
        let mut _cfg = kvm::KvmCapArmRmeConfigHash::default();
        let mut rme_cap_config: kvm_enable_cap = Default::default();
        rme_cap_config.cap = kvm::KvmCapArmRmeVm::CapRme as u32;
        rme_cap_config.args[0] = kvm::KvmCapArmRmeVm::CfgRealm as u64;
        rme_cap_config.args[1] = &mut _cfg as *mut kvm::KvmCapArmRmeConfigHash as *mut u64 as u64;

        kvm::kvm_vm_arm_rme_enable_cap(&vm_fd, &mut rme_cap_config)
    }

    fn create_realm_descriptor(&self, vm_fd: &VmFd) -> Result<(), Error> {
        let mut rme_cap_config: kvm_enable_cap = Default::default();
        rme_cap_config.cap = kvm::KvmCapArmRmeVm::CapRme as u32;
        rme_cap_config.args[0] = kvm::KvmCapArmRmeVm::CreateRd as u64;

        kvm::kvm_vm_arm_rme_enable_cap(&vm_fd, &mut rme_cap_config)
    }

    fn create_realm_dependency_devices(&self, vm_fd: &VmFd) -> Result<(DeviceFd, DeviceFd), Error> {
        let vgic_fd = kvm::kvm_vm_arm_create_irq_chip(&self.realm, &vm_fd);
        let vgic_its_fd = kvm::kvm_vm_arm_create_its_device(&self.realm, &vm_fd);
        if vgic_fd.is_err() || vgic_its_fd.is_err() {
            error!("VM: Failed to create required devices for realm.");
            return Err(vgic_fd.unwrap_err());
        };

        Ok((vgic_fd.unwrap(), vgic_its_fd.unwrap()))
    }
}
