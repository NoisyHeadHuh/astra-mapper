use std::slice;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQuery};
use windows_sys::s;

pub struct AstraDriver {
    handle: HANDLE,
}

#[repr(C)]
struct AstraInData {
    interface_type: u32,
    bus_number: u32,
    bus_address: u64,
    address_space: u32,
    view_size: u32,
}

const MAP_IOCTL: u32 = 0x80002008;

impl AstraDriver {
    pub fn open() -> Option<Self> {
        unsafe {
            let handle = CreateFileA(
                s!("\\\\.\\Astra32Device15\0"),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if (handle as i64) < 0 {
                None
            } else {
                Some(AstraDriver { handle: handle })
            }
        }
    }

    fn find_mapped_region(&self, low: u32) -> Option<*mut u8> {
        unsafe {
            let mut addy = std::ptr::null();
            let mut mbi: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
            while VirtualQuery(
                addy,
                &mut mbi as *mut MEMORY_BASIC_INFORMATION,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            {
                let base = mbi.BaseAddress as u64;
                let end = base + mbi.RegionSize as u64;

                if mbi.State == MEM_COMMIT {
                    let cmp = (low as u64) & !0xFFF;

                    if base as u32 == cmp as u32 {
                        return Some(base as *mut u8);
                    }
                }
                if end <= addy as u64 {
                    break;
                }
                addy = end as _;
            }
        }
        None
    }

    pub fn map(&self, address: u64, view_size: u32) -> Option<*mut u8> {
        unsafe {
            assert!(address & 0xFFF == 0);
            let mut in_data = AstraInData {
                interface_type: 0,
                bus_number: 0,
                bus_address: address,
                address_space: 0,
                view_size: view_size,
            };

            let mut out: u64 = 0;
            let mut bytes_returned: u32 = 0;
            DeviceIoControl(
                self.handle,
                MAP_IOCTL,
                std::mem::transmute(&mut in_data as *mut AstraInData),
                std::mem::size_of::<AstraInData>() as u32,
                std::mem::transmute(&mut out as *mut u64),
                8,
                &mut bytes_returned as *mut u32,
                std::ptr::null_mut(),
            );

            self.find_mapped_region(out as u32)
        }
    }

    pub fn map_slice(&self, address: u64, view_size: u32) -> Option<&'static mut [u8]> {
        unsafe {
            assert!(address & 0xFFF == 0);
            let mut in_data = AstraInData {
                interface_type: 0,
                bus_number: 0,
                bus_address: address,
                address_space: 0,
                view_size: view_size,
            };

            let mut out: u64 = 0;
            let mut bytes_returned: u32 = 0;
            DeviceIoControl(
                self.handle,
                MAP_IOCTL,
                std::mem::transmute(&mut in_data as *mut AstraInData),
                std::mem::size_of::<AstraInData>() as u32,
                std::mem::transmute(&mut out as *mut u64),
                8,
                &mut bytes_returned as *mut u32,
                std::ptr::null_mut(),
            );

            let ptr = self.find_mapped_region(out as u32)?;
            Some(slice::from_raw_parts_mut(ptr, view_size as usize))
        }
    }
}

impl Drop for AstraDriver {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
