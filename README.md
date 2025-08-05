# rm-windows

A powerful and safe command-line file/folder removal tool for Windows, built in Rust.  
Designed with built-in protections to prevent accidental deletion of critical system directories.

---

## Features

- Admin management:  
  - `rm.exe --add-admin` — Add an admin user  
  - `rm.exe --enable-2FA` / `rm.exe --disable-2FA` — Enable or disable two-factor authentication  
- Folder protection:  
  - `rm.exe -a FOLDER` — Protect a folder from deletion  
  - `rm.exe -d FOLDER` — Remove protection from a folder  
- File/Folder deletion flags:  
  - `-r` — Recursive deletion  
  - `-f` — Force deletion  
  - `-s` — Silent mode (no prompts)  
  - `-t` — Terminate locking processes  
- Default protections prevent deletion of critical folders such as:  
  - `C:\`  
  - `C:\Windows\**`  
  - `C:\System32\**`  
  - `C:\Users\**`

---

## Usage

```bash
rm.exe -a "C:\ImportantFolder"   # Protect a folder
rm.exe -d "C:\ImportantFolder"   # Remove protection
rm.exe -r -f -t "C:\SomeFolder"  # Force delete recursively, terminating locks
```
## Warning
This tool can delete files and folders permanently. Use with caution.
Make sure you understand the flags and protections before running commands.

## Building
Requires Rust toolchain installed. Clone and build with:
```bash
cargo build --release
```

## Pre built binaries
Go to [Pre built Binaries](https://github.com/ABI-Compute/RM_tool/releases/tag/v0.2.0)

## ⚠️ Important Note

Deleting folders directly under `C:\` (e.g. `C:\Qt`) may fail even with Administrator privileges, due to Windows permission restrictions.

In such cases, you may need to run `rm.exe` as the `SYSTEM` user using [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) from Microsoft Sysinternals.

> ⚠️ **Warning:** Running software as `SYSTEM` bypasses all Windows security.  
Only do this if you **fully understand the risks** — misuse can damage your system.

ABI-compute is **not responsible** for any unintended consequences or data loss caused by misuse.

### ✅ Example (only if you know what you're doing):

```bash
C:\Path\To\PsExec.exe -i -s rm.exe -rsft C:\Qt
```

## Replace C:\Path\To\PsExec.exe with the actual path of PsExec
