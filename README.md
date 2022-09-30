# Rust DLL Injector

This is a simple DLL injector written in Rust. <br/><br/>
It uses [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) so don't use it for games as it will most probably get detected by the anti-cheat.

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
