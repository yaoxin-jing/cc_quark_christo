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

use std::os::fd::FromRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use hashbrown::HashMap;
use kvm_bindings::kvm_enable_cap;
use kvm_ioctls::{Cap, DeviceFd, Kvm, VmFd};

use super::{resources::VmResources, VmType};
use crate::arch::vm::kvm::kvm_ioctl::KVM_SMCCC_FILTER_ACTION;
use crate::arch::vm::kvm::kvm_ioctl::kvm_arm_vm_smccc_filter;
use crate::arch::vm::kvm::kvm_ioctl::kvm_vm_arm_create_irq_chip;
use crate::arch::vm::kvm::kvm_ioctl::kvm_vm_arm_create_its_device;
use crate::arch::vm::tee::kvm::SMC_RSI_HOST_CALL;
use crate::arch::vm::tee::kvm::kvm_vm_arm_ipa_size;
use crate::arch::vm::tee::kvm::kvm_vm_arm_rme_enable_cap;
use crate::arch::vm::tee::kvm::kvm_vm_arm_rme_init_ipa_range;
use crate::arch::vm::tee::kvm::kvm_vm_arm_rme_populate_range;
use crate::arch::vm::tee::kvm::KvmCapArmRmeConfigHash;
use crate::arch::vm::tee::kvm::KvmCapArmRmeVm;
use crate::arch::vm::tee::kvm::KVM_VM_TYPE_ARM_REALM;
use crate::arch::vm::tee::realm::RealmVcpuXBootHelpData;
use crate::arch::vm::vcpu::kvm_vcpu::KvmAarch64Reg;
use crate::arch::vm::vcpu::ArchVirtCpu;
use crate::arch::VirtCpu;
use crate::kvm_vcpu::AlignedAllocate;
use crate::memmgr::MapOption;
use crate::print::LOG;
use crate::qlib::addr::{Addr, PageOpts};
use crate::qlib::common::Error;
use crate::qlib::kernel::kernel::{futex, timer};
use crate::qlib::kernel::vcpu::CPU_LOCAL;
use crate::qlib::kernel::SHARESPACE;
use crate::qlib::pagetable;
use crate::qlib::pagetable::PageTables;
use crate::qlib::ShareSpace;
use crate::runc::runtime::loader::Args;
use crate::runc::runtime::vm_type::resources::MemArea;
use crate::vmspace::tsot_agent::TSOT_AGENT;
use crate::vmspace::VMSpace;
use crate::{arch::tee::util::{adjust_addr_to_guest, adjust_addr_to_host},
    elf_loader::KernelELF, qlib::{config::CCMode, kernel::Kernel::{ENABLE_CC,
    IDENTICAL_MAPPING}, linux_def::MemoryDef}, runc::runtime::{vm::{self,
    VirtualMachine}, vm_type::resources::{MemAreaType, MemLayoutConfig}},
    KERNEL_IO_THREAD, PMA_KEEPER, QUARK_CONFIG, ROOT_CONTAINER_ID,
    SHARE_SPACE, URING_MGR, VMS};

pub mod realm {
    use kvm_bindings::kvm_userspace_memory_region;
    use kvm_ioctls::{DeviceFd, VmFd};
    use crate::arch::kvm::KvmUserSpaceMemoryRegion2;
    use crate::arch::vm::kvm::kvm_ioctl::kvm_arm_vgic_init_finalize;
    use crate::arch::vm::tee::kvm::{kvm_arm_rme_activate_realm,
        KvmCapArmRmeMeasurementAlgo,
        KVM_VM_TYPE_ARM_RPV_SIZE_BYTE};
    use crate::qlib::common::Error;

    #[derive(Debug)]
    pub struct vGic3 {
        pub size: u64,
        pub distributor_base: u64,
        pub redistributor_base: Option<u64>,
        pub its_base: Option<u64>,
        pub irq_lines: u64,
        pub vgic_fd: Option<DeviceFd>,
        pub its_fd: Option<DeviceFd>,
    }

    impl Default for vGic3 {
        fn default() -> Self {
            let _size = 0x2_0000; //2*64K
            let _vgic_end = 0x200_0000;
            let _dist_base = _vgic_end - _size;
            Self {
                size: _size,
                distributor_base: _dist_base,
                redistributor_base: None,
                its_base: None,
                irq_lines: 64,
                vgic_fd: None,
                its_fd: None,
            }
        }
    }

    impl vGic3 {
        pub fn adjuct_redist_base(&mut self, cpu_count: usize) {
            let _redist_base = self.distributor_base - cpu_count as u64 * self.size;
            let _its_base = _redist_base - cpu_count as u64 * self.size;
            self.redistributor_base.replace(_redist_base);
            self.its_base.replace(_its_base);
        }
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
                ipa_size: Self::QUARK_DEFAULT_REALM_IPA_SIZE,
                rpv_token: [0u8; KVM_VM_TYPE_ARM_RPV_SIZE_BYTE as usize],
                vgic3: vGic3::default(),
                sve: None,
                hash_algo: KvmCapArmRmeMeasurementAlgo::Sha256,
                vmid: 0,
            }
        }
    }

    impl Realm {
        const QUARK_DEFAULT_REALM_IPA_SIZE: u64 = 41;
        pub fn vgic_init_finalize(&self) -> Result<(), Error> {
            kvm_arm_vgic_init_finalize(self.vgic3.vgic_fd.as_ref(), self.vgic3.irq_lines)
        }

        pub fn activate_realm(&self, vm_fd: &mut VmFd) -> Result<(), Error> {
            kvm_arm_rme_activate_realm(vm_fd)
        }

        pub fn set_realm_memory(&mut self, vm_fd: &VmFd, _slot: u32, _guest_start: u64,
            _userspace_address: u64, _size: u64, protected: bool) -> Result<(), Error> {
            info!("VMM: Set MemRegion - Slot:{}, Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
                _slot, _guest_start, _userspace_address, _size >> 20);
            if protected {
                let mut guest_mem = crate::arch::kvm::KvmCreateGuestMemFd::new(_size, 0);
                let _guest_memfd =
                    crate::arch::kvm::kvm_ioctl::kvm_create_guest_memfd(vm_fd, &mut guest_mem)?;
                let mut _region = KvmUserSpaceMemoryRegion2::new(_slot, 0, _guest_start, _size,
                    _userspace_address, 0, _guest_memfd);
                crate::arch::kvm::kvm_ioctl::kvm_set_user_memory_region2(vm_fd, &mut _region)?;
            } else {
                let _region = kvm_userspace_memory_region {
                    slot: _slot,
                    guest_phys_addr: _guest_start,
                    memory_size: _size,
                    userspace_addr: _userspace_address,
                    flags: 0,
                };
                unsafe {
                    vm_fd.set_user_memory_region(_region).map_err(|e| {
                        Error::IOError(format!("Failed to set kvm slot-memory region :{}\
                            - error:{:?}", _region.slot, e))})?;
                }
            }
            Ok(())
        }
    }
}

use self::realm::Realm;

#[derive(Debug)]
pub struct VmCcRealm {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
    kernel_img_size: u64,
    cc_mode: CCMode,
    realm: Realm,
}

impl VmType for VmCcRealm {
    //NOTE: In the future we want to be able to customize the initialization through
    //      user provided configuration.
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error>
    where
        Self: Sized,
    {
        ENABLE_CC.store(true, Ordering::Release);
        crate::qlib::kernel::arch::tee::set_tee_type(CCMode::Cca);
        let _pod_id = args.expect("VM creation expects arguments").ID.clone();
        let default_min_vcpus = 3;
        let _emul_type: CCMode = CCMode::Cca;
        IDENTICAL_MAPPING.store(false, Ordering::Release);

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
        let mut _realm = Realm::default();
        let _kernel_img_size = (_vdso_address - _kernel_entry) + 3 * MemoryDef::PAGE_SIZE;
        let mut _mem_map: HashMap<MemAreaType, MemArea> = HashMap::new();
        _mem_map.insert(
            MemAreaType::PrivateHeapArea,
            MemArea {
                base_host: adjust_addr_to_host(MemoryDef::GUEST_PRIVATE_HEAP_OFFSET, _emul_type),
                base_guest: MemoryDef::GUEST_PRIVATE_HEAP_OFFSET,
                size: MemoryDef::GUEST_PRIVATE_HEAP_SIZE,
                guest_private: true,
                host_backedup: true,
            },
        );
        _mem_map.insert(
            MemAreaType::KernelArea,
            MemArea {
                base_host: adjust_addr_to_host(MemoryDef::PHY_LOWER_ADDR, _emul_type),
                base_guest: MemoryDef::PHY_LOWER_ADDR,
                size: MemoryDef::QKERNEL_IMAGE_SIZE,
                guest_private: true,
                host_backedup: true,
            },
        );
        _mem_map.insert(
            MemAreaType::FileMapArea,
            MemArea {
                base_host: MemoryDef::HOST_FILE_MAP_ADDRESS,
                base_guest: MemoryDef::HOST_FILE_MAP_ADDRESS,
                size: MemoryDef::HOST_FILE_MAP_SIZE,
                guest_private: false,
                host_backedup: true,
            },
        );
        _mem_map.insert(
            MemAreaType::SharedHeapArea,
            MemArea {
                base_host: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
                base_guest: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
                size: MemoryDef::GUEST_HOST_SHARED_HEAP_SIZE,
                guest_private: false,
                host_backedup: true,
            },
        );
        _mem_map.insert(
            MemAreaType::HypercallMmioArea,
            MemArea {
                base_host: u64::MAX,
                base_guest: MemoryDef::HYPERCALL_MMIO_BASE,
                size: MemoryDef::HYPERCALL_MMIO_SIZE,
                guest_private: false,
                host_backedup: false,
            },
        );
        let mem_layout_config = MemLayoutConfig {
            mem_area_map: _mem_map,
            kernel_stack_size: MemoryDef::DEFAULT_STACK_SIZE as usize,
            guest_mem_size: MemoryDef::KERNEL_MEM_INIT_REGION_SIZE * MemoryDef::ONE_GB,
        };

        let vm_resources = VmResources {
            min_vcpu_amount: default_min_vcpus,
            kernel_bin_path: _kernel_bin_path,
            vdso_bin_path: _vdso_bin_path,
            sandbox_uid_name: _sbox_uid_name,
            pod_id: _pod_id,
            mem_layout: mem_layout_config,
        };
        let vm_realm = Self {
            vm_resources,
            entry_address: _kernel_entry,
            vdso_address: _vdso_address,
            kernel_img_size: _kernel_img_size,
            cc_mode: _emul_type,
            realm: _realm,
        };
        let box_type: Box<dyn VmType> = Box::new(vm_realm);

        Ok((box_type, elf))
    }

    fn create_vm(mut self: Box<Self>, kernel_elf: KernelELF, args: Args)
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
            self.vm_resources.min_vcpu_amount = VMS.lock().vcpuCount;
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

        let (_, pheap, _) = self.vm_resources.mem_area_info(MemAreaType::PrivateHeapArea).unwrap();
        let _auto_start = VMS.lock().args.as_ref().unwrap().AutoStart;
        let _vcpus = self.vm_vcpu_initialize(&_kvm, &vm_fd, cpu_count, self.entry_address,
                _auto_start, Some(pheap), None).expect("VM creation failed on vcpu creation.");

        self.post_memory_initialize(&mut vm_fd).expect("VM post memory initialization failed");
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

    fn vm_space_initialize(&self, vcpu_count: usize, args: Args) -> Result<(), Error> {
        let vms = &mut VMS.lock();
        vms.vcpuCount = vcpu_count.max(self.vm_resources.min_vcpu_amount);
        vms.cpuAffinit = true;
        vms.RandomVcpuMapping();
        vms.controlSock = args.ControlSock;
        vms.vdsoAddr = self.vdso_address;
        vms.pivot = args.Pivot;
        if let Some(id) = args.Spec.annotations.get(
            self.vm_resources.sandbox_uid_name.as_str()) {
            vms.podUid = id.clone();
        } else {
            info!("No sandbox id found in specification.");
        }

        let(_, rfmap_address, rfmap_size) = self.vm_resources
            .mem_area_info(MemAreaType::FileMapArea).unwrap();
        let mut rfmap = MapOption::New();
        rfmap.Addr(rfmap_address).Len(rfmap_size).ProtoRead()
            .ProtoWrite().MapShare().MapAnan().MapFixed().MapLocked();
        let mmap_addr = rfmap.MMap().expect("Failed to mmap");
        assert_eq!(mmap_addr, rfmap_address,
            "VMM: mmap Realm file-map area not in requested address");
        PMA_KEEPER.Init(rfmap_address, rfmap_size);
        PMA_KEEPER.InitHugePages();

        vms.pageTables = PageTables::New(&vms.allocator)?;

        let block_size = pagetable::HugePageType::MB2;
        for (_mt, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            info!("VM: Creating mapping for {}", _mt.to_string());
            if *_mt == MemAreaType::HypercallMmioArea {
                let mut page_opt = PageOpts::Zero();
                page_opt.SetWrite().SetGlobal().SetPresent()
                    .SetAccessed().SetMMIOPage();
                vms.KernelMap(Addr(_ma.base_guest), Addr(_ma.base_guest + _ma.size),
                    Addr(_ma.base_guest), page_opt.Val())?;
            } else {
                let mut entry_opt = PageOpts::KernelReadWrite();
                entry_opt.SetBlock();
                if vms.KernelMapHugeTable(Addr(_ma.base_guest),
                    Addr(_ma.base_guest + _ma.size), Addr(_ma.base_guest),
                    entry_opt.Val(), block_size).unwrap() == false {
                        panic!("VM: Failed to map {}", _mt.to_string());
                }
            }
        }
        debug!("VMM: Create initial kernel page-table done.");
        vms.args = Some(args);

        Ok(())
    }

    fn init_share_space(vcpu_count: usize, control_sock: i32, rdma_svc_cli_sock: i32,
        pod_id: [u8; 64], share_space_addr: Option<u64>, _has_global_mem_barrier: Option<bool>)
        -> Result<(), Error>
    where
        Self: Sized,
    {
        use core::sync::atomic;
        crate::GLOBAL_ALLOCATOR.vmLaunched.store(true, atomic::Ordering::SeqCst);
        debug!("VMM: Initilize shared space.");
        let shared_space_obj = unsafe {
            &mut *(share_space_addr.expect(
                "Failed to initialize shared space in host - \
                    shared-space-table address is missing") as *mut ShareSpace)};
        let default_share_space_table = ShareSpace::New();
        let def_sh_space_tab_size = core::mem::size_of_val(&default_share_space_table);
        let sh_space_obj_size = core::mem::size_of_val(shared_space_obj);
        assert!(sh_space_obj_size == def_sh_space_tab_size,
            "Guest passed shared-space address does not match to a shared-space object. \
                Expected obj size:{:#x} - found:{:#x}",
            def_sh_space_tab_size, sh_space_obj_size);
        unsafe {
            core::ptr::write(shared_space_obj as *mut ShareSpace,
                default_share_space_table);
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

    fn create_kvm_vm(&mut self, kvm_fd: i32) -> Result<(kvm_ioctls::Kvm, kvm_ioctls::VmFd), Error> {
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        if kvm.check_extension(Cap::ImmediateExit) == false {
            panic!("Can not create VM - KVM_CAP_IMMEDIATE_EXIT is not supported.");
        }
        if kvm.check_extension(Cap::ArmVmIPASize) == false {
            panic!("Can not create VM - Set IPA_SIZE:{} not supported.",
                self.realm.ipa_size);
        }
        let ipa_limit = kvm.get_host_ipa_limit();
        println!("VMM: Supported IPA-Limit:{}.", ipa_limit);
        let vm_type = KVM_VM_TYPE_ARM_REALM | kvm_vm_arm_ipa_size(self.realm.ipa_size);
        let vm_fd = kvm.create_vm_with_type(vm_type)
            .map_err(|e| Error::IOError(format!("Failed to crate a kvm-vm with error:{:?}", e)))?;

        self.configure_realm(&vm_fd);
        let (vgic_fd, its_fd): (DeviceFd, DeviceFd) = self
            .create_realm_dependency_devices(&vm_fd)
            .expect("Can not create VM - failed to create devices.");
        self.realm.vgic3.vgic_fd = Some(vgic_fd);
        self.realm.vgic3.its_fd = Some(its_fd);

        Ok((kvm, vm_fd))
    }

    fn vm_memory_initialize(&mut self, vm_fd: &kvm_ioctls::VmFd) -> Result<(), Error> {
        info!("VM creation: KVM guest memory initialization.");
        let mut _slot = 1;
        for (_mt, _ma) in &self.vm_resources.mem_layout.mem_area_map {
            if _ma.host_backedup {
                self.realm.set_realm_memory(vm_fd, _slot, _ma.base_guest,
                    _ma.base_host, _ma.size, _ma.guest_private)
                    .expect("VM: failed to register memory for Realm");
                _slot += 1;
            }
        }
        Ok(())
    }

    fn post_memory_initialize(&mut self, vm_fd: &mut VmFd) -> Result<(), Error> {
        let (_, gh_base, size) = self.vm_resources
            .mem_area_info(MemAreaType::PrivateHeapArea).unwrap();
        info!("VM: Init Realm-IPA range memory - GustPrivateHeap - GuestBase:{:#0x} - Size:{}MB.",
            gh_base, size >> 20);
        kvm_vm_arm_rme_init_ipa_range(vm_fd, gh_base, size)
            .expect("VM: Failed to init IPA for region: Kernel");
        info!("VM: Init Realm-IPA range memory - Kernel - GuestBase:{:#0x} - Size:{}MB.",
            self.entry_address, self.kernel_img_size >> 20);
        kvm_vm_arm_rme_init_ipa_range(vm_fd, self.entry_address, self.kernel_img_size)
            .expect("VM: Failed to init IPA for region: Kernel");

        info!("VM: Populate Realm memory - Kernel.");
        kvm_vm_arm_rme_populate_range(vm_fd, self.entry_address, self.kernel_img_size)
            .expect("VM: Failed to populate for region: Kernel");

        info!("VM: Populate Realm memory - Guest Heap.");
        kvm_vm_arm_rme_populate_range(vm_fd, gh_base, size)
            .expect("VM: Failed to populate for region: Guest Heap");

        Ok(())
    }

    fn vm_vcpu_initialize(&self, kvm: &kvm_ioctls::Kvm, vm_fd: &kvm_ioctls::VmFd,
        total_vcpus: usize, entry_addr: u64, auto_start: bool, page_allocator_addr: Option<u64>,
        share_space_addr: Option<u64>) -> Result<Vec<Arc<ArchVirtCpu>>, Error> {
        let mut vcpus: Vec<Arc<ArchVirtCpu>> = Vec::with_capacity(total_vcpus);

        for vcpu_id in 0..total_vcpus {
            debug!("VMM - Initilize vCPU-{}", vcpu_id);
            let vcpu = Arc::new(ArchVirtCpu::new_vcpu(vcpu_id as usize, total_vcpus,
                &vm_fd, entry_addr, page_allocator_addr, share_space_addr, auto_start,
                self.vm_resources.mem_layout.kernel_stack_size, Some(&kvm), self.cc_mode)?);
            vcpus.push(vcpu);
        }
        let slice_size = total_vcpus * std::mem::size_of::<RealmVcpuXBootHelpData>();
        let boot_help_data_base: u64 =
            AlignedAllocate(slice_size, MemoryDef::PAGE_SIZE as usize, false)
                .expect("Failed to reserve buffer for boot aid information.");
        let data_slice = unsafe {
            std::slice::from_raw_parts_mut(
                adjust_addr_to_host(boot_help_data_base, self.cc_mode)
                    as *mut RealmVcpuXBootHelpData, total_vcpus)
        };
        debug!("VMM: Reserved addr:{:#0x} - size:{} Bytes, for boot aid information.",
            boot_help_data_base, slice_size);
        let (_, gh_base, _) = self.vm_resources
            .mem_area_info(MemAreaType::PrivateHeapArea).unwrap();
        let mut i = 0;
        for vcpu in &mut vcpus {
            vcpu.vcpu_init().expect("VM: Failed to initialize vCPU");
            let mpidr = vcpu.vcpu_base.vcpu_fd.get_one_reg(KvmAarch64Reg::Mpidr as u64)
                .expect("Failed to get MPIDR");
            let _stack_base_offset = vcpu.vcpu_base.topStackAddr - gh_base;
            if _stack_base_offset >= 4 * MemoryDef::ONE_GB {
                panic!("VMM: Failed to prepare vCPU - stack offset is bigger than 4GB.");
            }
            data_slice[i] = RealmVcpuXBootHelpData::new(mpidr, _stack_base_offset as u32);
            debug!("VMM: Boot help data: {} - MPIDR:{:#0x} - SP_EL1:{:#0x} - SP_offset:{:#0x}.",
                i, mpidr, vcpu.vcpu_base.topStackAddr, _stack_base_offset);
            vcpu.initialize_sys_registers()
                .expect("VM: Failed to initialize systetem registers");
            vcpu.initialize_cpu_registers()
                .expect("VM: Failed to initialize GPR-registers");
            i += 1;
        }
        vcpus[0].vcpu_base.vcpu_fd.set_one_reg(KvmAarch64Reg::X7 as u64, boot_help_data_base)
            .expect("VMM: vCPU failed to set X7:BootHelpData-base");
        VMS.lock().vcpus = vcpus.clone();
        Ok(vcpus)
    }

    fn post_vm_initialize(&mut self, vm_fd: &mut VmFd) -> Result<(), Error> {
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

    fn get_type(&self) -> CCMode {
        CCMode::Cca
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
        let mut _cfg = KvmCapArmRmeConfigHash::default();
        let mut rme_cap_config: kvm_enable_cap = Default::default();
        rme_cap_config.cap = KvmCapArmRmeVm::CapRme as u32;
        rme_cap_config.args[0] = KvmCapArmRmeVm::CfgRealm as u64;
        rme_cap_config.args[1] = &mut _cfg as *mut KvmCapArmRmeConfigHash as *mut u64 as u64;
        kvm_vm_arm_rme_enable_cap(vm_fd, &mut rme_cap_config)
            .expect("VM: failed to personalize Realm");

        Ok(())
    }

    fn create_realm_descriptor(&self, vm_fd: &VmFd) -> Result<(), Error> {
        let mut rme_cap_config: kvm_enable_cap = Default::default();
        rme_cap_config.cap = KvmCapArmRmeVm::CapRme as u32;
        rme_cap_config.args[0] = KvmCapArmRmeVm::CreateRd as u64;
        kvm_vm_arm_rme_enable_cap(&vm_fd, &mut rme_cap_config)
    }

    fn create_realm_dependency_devices(&mut self, vm_fd: &VmFd) -> Result<(DeviceFd, DeviceFd), Error> {
        self.realm.vgic3.adjuct_redist_base(self.vm_resources.min_vcpu_amount);
        let vgic_fd = kvm_vm_arm_create_irq_chip(vm_fd, &self.realm.vgic3);
        let vgic_its_fd = kvm_vm_arm_create_its_device(vm_fd, &self.realm.vgic3);
        if vgic_fd.is_err() || vgic_its_fd.is_err() {
            error!("VM: Failed to create required devices for realm.");
            return Err(vgic_fd.unwrap_err());
        };
        let _ = kvm_arm_vm_smccc_filter(&vm_fd, SMC_RSI_HOST_CALL, 1u32,
            KVM_SMCCC_FILTER_ACTION::FwdToUser as u8)
            .expect("VMM: KVM failed to set smccc filter for RSI_HOST_CALL");

        Ok((vgic_fd.unwrap(), vgic_its_fd.unwrap()))
    }
}
