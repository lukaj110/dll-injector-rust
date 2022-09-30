# Rust DLL Injector

This is a simple DLL injector written in Rust. <br/>

It uses [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) so don't use it for games as it will most probably get detected by the anti-cheat.

Keep in mind that this won't work if the DLL is managed (.NET). This feature might be added in the future.

## Usage

### Command line

```bash
dll-injector-rust.exe [Process ID (PID)] [DLL Path]
```

### Development

```bash
cargo run -- [Process ID (PID)] [DLL Path]
```

### Parameters

Alternatively you may just run the executable without any parameters and enter them in the console interactively.

### Testing

You can use the provided `Test.dll` file to test the injector. All it does is display a message box when injected into a process and when the process exits.
