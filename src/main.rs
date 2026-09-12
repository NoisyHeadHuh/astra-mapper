use std::collections::HashMap;

use goblin::pe::relocation::IMAGE_REL_BASED_DIR64;
use scroll::ctx::TryIntoCtx;
use superfetch::MemoryMap;
use windows_sys::Win32::System::Memory;

use crate::{astra::AstraDriver, system::translate_v2p};

mod astra;
mod ntoskrnl;
mod system;

const BEEP_IOCTL_OFFSET: system::Vaddr = 0x1290;

fn map_virtual_address(mm: &MemoryMap, address: u64, size: usize) -> &'static mut [u8] {
    let astra = AstraDriver::open().unwrap();
    let paddr = mm.translate(address as _).unwrap_or(0);
    if paddr == 0 {
        panic!("Failed to translate addy");
    }
    let slice = astra.map_slice(paddr, size as u32).unwrap();
    slice
}

fn main() {
    let mut kernel = ntoskrnl::Kernel::new();

    let driver_bytes = std::fs::read("hello_world_driver.dll").unwrap();
    let driver_object = match goblin::Object::parse(&driver_bytes).unwrap() {
        goblin::Object::PE(pe) => pe,
        _ => {
            panic!("driver is not a PE")
        }
    };

    let size_of_image = driver_object
        .header
        .optional_header
        .unwrap()
        .windows_fields
        .size_of_image as usize;

    let mut driver_fixed = vec![0x0u8; size_of_image];

    driver_object
        .header
        .try_into_ctx(&mut driver_fixed, scroll::Endian::Little)
        .unwrap();

    for sec in &driver_object.sections {
        let raw_data = sec.pointer_to_raw_data as usize;
        let size_raw_data = sec.size_of_raw_data as usize;
        let vaddr = sec.virtual_address as usize;
        let virtual_size = sec.virtual_size as usize;
        driver_fixed[vaddr..vaddr + size_raw_data]
            .copy_from_slice(&driver_bytes[raw_data..raw_data + size_raw_data]);
        unsafe {
            println!(
                "{} at vaddr: {:X} raw: {:X} vsize: {:X}",
                std::str::from_utf8_unchecked(&sec.name),
                vaddr,
                raw_data,
                virtual_size
            );
        }
    }

    //fix imports
    for i in driver_object.imports {
        //println!("{}", &i.name);
        let new_address = kernel.get_export(&i.name).unwrap();
        driver_fixed[i.offset..i.offset + 8].copy_from_slice(&new_address.to_ne_bytes());
        println!("Fixed import {} new address is {:X}", i.name, new_address);
    }

    //fix relocs

    println!("Driver len: {:X}", driver_fixed.len());

    let driver_base = kernel.ex_allocate_pool_with_tag(driver_fixed.len(), 0x48484848);
    let mm = unsafe {
        match MemoryMap::snapshot() {
            Ok(m) => m,
            Err(e) => panic!("Failed to take memorymap snapshot"),
        }
    };

    let driver_slice = map_virtual_address(&mm, driver_base, 0x1000);
    driver_slice.copy_from_slice(&driver_fixed[..0x1000]);

    let delta = driver_base - driver_object.image_base;
    if let Some(relocation_data) = driver_object.relocation_data {
        for b in relocation_data.blocks() {
            for w in b.as_ref().unwrap().words() {
                if w.as_ref().unwrap().reloc_type() == IMAGE_REL_BASED_DIR64 as u8 {
                    let target_rva =
                        b.as_ref().unwrap().rva as usize + w.unwrap().offset() as usize;
                    let old_value = u64::from_le_bytes(
                        driver_fixed[target_rva..target_rva + 8].try_into().unwrap(),
                    );

                    let new_value = old_value.wrapping_add(delta);

                    driver_fixed[target_rva..target_rva + 8]
                        .copy_from_slice(&new_value.to_le_bytes());
                }
            }
        }
    }

    println!("Driver alloc {:X}", driver_base);

    for s in &driver_object.sections {
        for offset in (0x0..s.virtual_size).step_by(0x1000) {
            let amount = (s.virtual_size - offset).min(0x1000);
            let map_address = driver_base + s.virtual_address as u64 + offset as u64;
            let driver_slice = map_virtual_address(&mm, map_address, amount as usize);
            println!(
                "[{}] Mapping from {:X} to {:X}",
                s.name().unwrap(),
                map_address,
                map_address + amount as u64
            );
            let va = s.virtual_address as usize + offset as usize;
            driver_slice.copy_from_slice(&driver_fixed[va..va + amount as usize])
        }
    }

    //for chunk in driver_fixed[0x1000..].chunks(0x1000) {
    //    println!("{:X}", chunk.len())
    //}

    let ep = driver_base
        + driver_object
            .header
            .optional_header
            .unwrap()
            .standard_fields
            .address_of_entry_point as u64;
    println!("EP at: {:X}", ep);

    kernel.jump_to(ep);

    std::fs::write("wata.bin", driver_fixed).unwrap();
}
