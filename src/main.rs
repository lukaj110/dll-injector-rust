use bytesize::ByteSize;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use sysinfo::{Pid, PidExt, ProcessExt, SystemExt};
use um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};
use winapi::ctypes::c_void;
use winapi::*;

fn get_dll_path() -> Option<String> {
    print!(
        "Enter the DLL Path [Absolute or Relative to '{}']: ",
        std::env::current_dir().unwrap().to_str().unwrap()
    );
    std::io::stdout().flush().unwrap();

    let mut dll_path = String::new();
    std::io::stdin().read_line(&mut dll_path).unwrap();
    dll_path = dll_path.trim().to_string().to_lowercase();

    if !dll_path.ends_with(".dll") {
        println!("Invalid path to DLL.");
        return None;
    }

    let path = fs::canonicalize(dll_path);

    if !path.is_ok() {
        println!("Invalid path to DLL.");
        return None;
    }
    return Some(path.unwrap().to_str().unwrap().to_string());
}

fn get_input_process() -> Option<usize> {
    print!("Enter the process name to be injected: ");

    std::io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    let mut process_name = String::new();
    std::io::stdin().read_line(&mut process_name).unwrap();

    process_name = process_name.trim().to_string();

    let mut process_array: Vec<&sysinfo::Process> = vec![];

    let system = sysinfo::System::new_all();

    for (_, process) in system.processes() {
        if process
            .name()
            .to_lowercase()
            .contains(&process_name.to_lowercase())
        {
            process_array.push(process);
        }
    }

    if process_array.len() == 0 {
        println!("No processes found with the name {}", process_name);
        return None;
    }

    if process_array.len() == 1 {
        return Some(process_array[0].pid().as_u32() as usize);
    }

    process_array.sort_by(|a, b| b.memory().cmp(&a.memory()));

    for (i, process) in process_array.iter().enumerate() {
        let byte_size = ByteSize::b(process.memory());
        println!(
            "[{}]: {} - {} in memory",
            i + 1,
            process.name(),
            byte_size.to_string()
        );
    }

    print!("Enter the ID of the process you want to inject into: ");

    std::io::stdout().flush().expect("Failed to flush stdout");

    std::io::stdin().read_line(&mut input).unwrap();

    return Some(
        process_array[input.trim().parse().unwrap_or(1) - 1]
            .pid()
            .as_u32() as usize,
    );
}

fn main() {
    let dll_option = get_dll_path();

    if dll_option.is_none() {
        return;
    }

    let dll_path = dll_option.unwrap();

    let system = sysinfo::System::new_all();

    let pid_option = get_input_process();

    if pid_option.is_none() {
        return;
    }

    let process_pid = pid_option.unwrap();

    let process = system.process(Pid::from(process_pid)).unwrap();

    println!("\nInjecting into {}, PID {}", process.name(), process.pid());

    unsafe {
        fn close_with_message(handle: *mut c_void, message: &str) {
            if handle != std::ptr::null_mut() {
                unsafe {
                    um::handleapi::CloseHandle(handle);
                }
                println!("{}", message);
            }
        }

        let process_handle = um::processthreadsapi::OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            process_pid as u32,
        );

        if process_handle.is_null() {
            println!("Failed to open process");
            return;
        }

        println!("Process handle: {:?}", process_handle);

        let dll_path_address = um::memoryapi::VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            dll_path.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        if dll_path_address.is_null() {
            return close_with_message(process_handle, "Failed to allocate memory for DLL");
        }

        println!("DLL path address: {:?}", dll_path_address);

        let mem = um::memoryapi::WriteProcessMemory(
            process_handle,
            dll_path_address,
            dll_path.as_ptr() as *const _,
            dll_path.len(),
            std::ptr::null_mut(),
        );

        if mem == 0 {
            return close_with_message(process_handle, "Failed to write to memory");
        }

        let lp_module_name = CString::new("kernel32.dll").unwrap();
        let lp_proc_name = CString::new("LoadLibraryA").unwrap();

        let load_library_address = um::libloaderapi::GetProcAddress(
            um::libloaderapi::GetModuleHandleA(lp_module_name.as_ptr()),
            lp_proc_name.as_ptr(),
        );

        if load_library_address.is_null() {
            return close_with_message(process_handle, "Failed to get address of LoadLibraryA");
        }

        let remote_thread = um::processthreadsapi::CreateRemoteThread(
            process_handle,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(load_library_address)),
            dll_path_address,
            0,
            std::ptr::null_mut(),
        );

        if remote_thread.is_null() {
            return close_with_message(process_handle, "Failed to create remote thread");
        }

        println!("Remote thread: {:?}", remote_thread);

        um::handleapi::CloseHandle(process_handle);
    }
}
