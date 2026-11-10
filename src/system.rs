use std::ffi::c_void;
use superfetch::MemoryMap;
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

pub type Vaddr = usize;
pub type Paddr = usize;

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
struct RTL_PROCESS_MODULES {
    NumberOfModules: u32,
    Modules: RTL_PROCESS_MODULE_INFORMATION,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
struct RTL_PROCESS_MODULE_INFORMATION {
    Section: *mut c_void,
    MappedBase: *mut c_void,
    ImageBase: *mut c_void,
    ImageSize: u32,
    Flags: u32,
    LoadOrderIndex: u16,
    InitOrderIndex: u16,
    LoadCount: u16,
    OffsetToFileName: u16,
    FullPathName: [u8; 256],
}

pub fn get_kernel_module_address<S: AsRef<str>>(module_name: S) -> Option<Vaddr> {
    let mut buffer = std::ptr::null_mut();
    let mut buffer_size: u32 = 0;
    //11 is SystemModuleInformation
    unsafe {
        let _status =
            NtQuerySystemInformation(11, buffer, buffer_size, &mut buffer_size as *mut u32);
        buffer = VirtualAlloc(
            std::ptr::null_mut(),
            buffer_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        let status =
            NtQuerySystemInformation(11, buffer, buffer_size, &mut buffer_size as *mut u32);

        if status < 0 {
            VirtualFree(buffer, 0, MEM_RELEASE);
            return None;
        }

        let process_modules = buffer as *mut RTL_PROCESS_MODULES;
        let raw_modules = &(*process_modules).Modules as *const RTL_PROCESS_MODULE_INFORMATION;
        let modules =
            std::slice::from_raw_parts(raw_modules, (*process_modules).NumberOfModules as usize);
        for m in modules {
            let filename = &m.FullPathName[m.OffsetToFileName as usize..];
            let filename = std::str::from_utf8_unchecked(filename).to_ascii_lowercase();
            if filename.starts_with(module_name.as_ref()) {
                return Some(m.ImageBase as Vaddr);
            }
        }
    }
    None
}

pub fn translate_v2p(mm: &MemoryMap, vaddr: Vaddr) -> Paddr {
    match mm.translate(vaddr as _) {
        Ok(addr) => addr as Paddr,
        Err(_) => panic!("Failed to translate vaddr to paddr"),
    }
}
