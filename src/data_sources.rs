// Data Sources - Comprehensive forensic artifact locations
// Sumber data lengkap untuk cleanup

#![allow(dead_code)]

use std::path::PathBuf;

pub struct ForensicArtifact {
    pub name: String,
    pub paths: Vec<String>,
    pub description: String,
    pub platform: String,
}

pub fn get_all_artifacts() -> Vec<ForensicArtifact> {
    let mut artifacts = Vec::new();
    
    // Windows Artifacts
    artifacts.extend(vec![
        ForensicArtifact {
            name: "Prefetch".to_string(),
            paths: vec![
                "C:\\Windows\\Prefetch\\*.pf".to_string(),
            ],
            description: "Program execution tracking".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "ShimCache".to_string(),
            paths: vec![
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache".to_string(),
            ],
            description: "Application compatibility cache".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "AmCache".to_string(),
            paths: vec![
                "C:\\Windows\\AppCompat\\Programs\\Amcache.hve".to_string(),
            ],
            description: "Application execution history".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "BAM/DAM".to_string(),
            paths: vec![
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings".to_string(),
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings".to_string(),
            ],
            description: "Background Activity Moderator".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "UserAssist".to_string(),
            paths: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist".to_string(),
            ],
            description: "GUI program execution tracking".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "RecentDocs".to_string(),
            paths: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs".to_string(),
            ],
            description: "Recently opened documents".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "JumpLists".to_string(),
            paths: vec![
                "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations".to_string(),
                "%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations".to_string(),
            ],
            description: "Recent files and tasks".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Shellbags".to_string(),
            paths: vec![
                "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags".to_string(),
                "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU".to_string(),
                "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU".to_string(),
            ],
            description: "Folder access history".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "LNK Files".to_string(),
            paths: vec![
                "%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk".to_string(),
            ],
            description: "Shortcut files with metadata".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Thumbcache".to_string(),
            paths: vec![
                "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db".to_string(),
            ],
            description: "Thumbnail cache".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "IconCache".to_string(),
            paths: vec![
                "%LOCALAPPDATA%\\IconCache.db".to_string(),
            ],
            description: "Icon cache database".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "SRUM".to_string(),
            paths: vec![
                "C:\\Windows\\System32\\sru\\SRUDB.dat".to_string(),
            ],
            description: "System Resource Usage Monitor".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Event Logs".to_string(),
            paths: vec![
                "C:\\Windows\\System32\\winevt\\Logs\\*.evtx".to_string(),
            ],
            description: "Windows event logs".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Registry Hives".to_string(),
            paths: vec![
                "C:\\Windows\\System32\\config\\SAM".to_string(),
                "C:\\Windows\\System32\\config\\SECURITY".to_string(),
                "C:\\Windows\\System32\\config\\SOFTWARE".to_string(),
                "C:\\Windows\\System32\\config\\SYSTEM".to_string(),
                "%USERPROFILE%\\NTUSER.DAT".to_string(),
            ],
            description: "Registry database files".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "USN Journal".to_string(),
            paths: vec![
                "$Extend\\$UsnJrnl".to_string(),
            ],
            description: "NTFS change journal".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "$MFT".to_string(),
            paths: vec![
                "$MFT".to_string(),
            ],
            description: "Master File Table".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "$LogFile".to_string(),
            paths: vec![
                "$LogFile".to_string(),
            ],
            description: "NTFS transaction log".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Recycle Bin".to_string(),
            paths: vec![
                "C:\\$Recycle.Bin".to_string(),
            ],
            description: "Deleted files".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Pagefile".to_string(),
            paths: vec![
                "C:\\pagefile.sys".to_string(),
            ],
            description: "Virtual memory swap file".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Hiberfil".to_string(),
            paths: vec![
                "C:\\hiberfil.sys".to_string(),
            ],
            description: "Hibernation file".to_string(),
            platform: "windows".to_string(),
        },
        ForensicArtifact {
            name: "Swapfile".to_string(),
            paths: vec![
                "C:\\swapfile.sys".to_string(),
            ],
            description: "Modern swap file".to_string(),
            platform: "windows".to_string(),
        },
    ]);
    
    // Linux Artifacts
    artifacts.extend(vec![
        ForensicArtifact {
            name: "Bash History".to_string(),
            paths: vec![
                "~/.bash_history".to_string(),
                "~/.zsh_history".to_string(),
                "~/.sh_history".to_string(),
            ],
            description: "Command line history".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "System Logs".to_string(),
            paths: vec![
                "/var/log/syslog".to_string(),
                "/var/log/messages".to_string(),
                "/var/log/auth.log".to_string(),
                "/var/log/secure".to_string(),
                "/var/log/kern.log".to_string(),
            ],
            description: "System log files".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Journal".to_string(),
            paths: vec![
                "/var/log/journal".to_string(),
                "/run/log/journal".to_string(),
            ],
            description: "Systemd journal".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Wtmp/Utmp".to_string(),
            paths: vec![
                "/var/log/wtmp".to_string(),
                "/var/log/btmp".to_string(),
                "/var/run/utmp".to_string(),
            ],
            description: "Login records".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Last Log".to_string(),
            paths: vec![
                "/var/log/lastlog".to_string(),
            ],
            description: "Last login information".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Cron Logs".to_string(),
            paths: vec![
                "/var/log/cron".to_string(),
                "/var/log/cron.log".to_string(),
            ],
            description: "Scheduled task logs".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Recently Used".to_string(),
            paths: vec![
                "~/.local/share/recently-used.xbel".to_string(),
            ],
            description: "Recently accessed files".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Thumbnails".to_string(),
            paths: vec![
                "~/.cache/thumbnails".to_string(),
                "~/.thumbnails".to_string(),
            ],
            description: "Image thumbnails".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Trash".to_string(),
            paths: vec![
                "~/.local/share/Trash".to_string(),
            ],
            description: "Deleted files".to_string(),
            platform: "linux".to_string(),
        },
        ForensicArtifact {
            name: "Swap".to_string(),
            paths: vec![
                "/swapfile".to_string(),
                "/swap.img".to_string(),
            ],
            description: "Swap file".to_string(),
            platform: "linux".to_string(),
        },
    ]);
    
    // Browser Artifacts (Cross-platform)
    artifacts.extend(vec![
        ForensicArtifact {
            name: "Chrome History".to_string(),
            paths: vec![
                "~/.config/google-chrome/Default/History".to_string(),
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History".to_string(),
                "~/Library/Application Support/Google/Chrome/Default/History".to_string(),
            ],
            description: "Chrome browsing history".to_string(),
            platform: "all".to_string(),
        },
        ForensicArtifact {
            name: "Chrome Cookies".to_string(),
            paths: vec![
                "~/.config/google-chrome/Default/Cookies".to_string(),
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies".to_string(),
            ],
            description: "Chrome cookies".to_string(),
            platform: "all".to_string(),
        },
        ForensicArtifact {
            name: "Chrome Cache".to_string(),
            paths: vec![
                "~/.cache/google-chrome".to_string(),
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache".to_string(),
            ],
            description: "Chrome cache".to_string(),
            platform: "all".to_string(),
        },
        ForensicArtifact {
            name: "Firefox Places".to_string(),
            paths: vec![
                "~/.mozilla/firefox/*.default*/places.sqlite".to_string(),
                "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default*\\places.sqlite".to_string(),
            ],
            description: "Firefox history and bookmarks".to_string(),
            platform: "all".to_string(),
        },
        ForensicArtifact {
            name: "Firefox Cookies".to_string(),
            paths: vec![
                "~/.mozilla/firefox/*.default*/cookies.sqlite".to_string(),
                "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default*\\cookies.sqlite".to_string(),
            ],
            description: "Firefox cookies".to_string(),
            platform: "all".to_string(),
        },
        ForensicArtifact {
            name: "Firefox Cache".to_string(),
            paths: vec![
                "~/.cache/mozilla/firefox/*.default*/cache2".to_string(),
                "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*.default*\\cache2".to_string(),
            ],
            description: "Firefox cache".to_string(),
            platform: "all".to_string(),
        },
    ]);
    
    artifacts
}

pub fn get_forensic_tools() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // Memory Forensics
        ("volatility", "Memory forensics framework", "memory"),
        ("volatility3", "Volatility 3", "memory"),
        ("rekall", "Memory forensics", "memory"),
        ("redline", "FireEye memory analysis", "memory"),
        ("memoryze", "Mandiant memory forensics", "memory"),
        ("windbg", "Windows debugger", "memory"),
        
        // Disk Forensics
        ("autopsy", "Digital forensics platform", "disk"),
        ("ftk", "Forensic Toolkit", "disk"),
        ("ftkimager", "FTK Imager", "disk"),
        ("encase", "EnCase forensics", "disk"),
        ("xways", "X-Ways Forensics", "disk"),
        ("sleuthkit", "The Sleuth Kit", "disk"),
        ("tsk", "TSK tools", "disk"),
        
        // Network Forensics
        ("wireshark", "Network protocol analyzer", "network"),
        ("tshark", "Terminal Wireshark", "network"),
        ("tcpdump", "Packet capture", "network"),
        ("networkminer", "Network forensics", "network"),
        ("zeek", "Network security monitor", "network"),
        ("bro", "Zeek (old name)", "network"),
        ("snort", "IDS/IPS", "network"),
        
        // Live Response
        ("procmon", "Process Monitor", "live"),
        ("procexp", "Process Explorer", "live"),
        ("processhacker", "Process Hacker", "live"),
        ("sysmon", "System Monitor", "live"),
        ("osquery", "OS query tool", "live"),
        
        // Reverse Engineering
        ("ida", "IDA Pro", "reverse"),
        ("ida64", "IDA Pro 64-bit", "reverse"),
        ("ghidra", "NSA reverse engineering", "reverse"),
        ("radare2", "Reverse engineering framework", "reverse"),
        ("r2", "Radare2 short name", "reverse"),
        ("ollydbg", "OllyDbg debugger", "reverse"),
        ("x64dbg", "x64 debugger", "reverse"),
        ("x32dbg", "x32 debugger", "reverse"),
        ("binaryninja", "Binary Ninja", "reverse"),
        
        // Malware Analysis
        ("cuckoo", "Cuckoo Sandbox", "malware"),
        ("joesandbox", "Joe Sandbox", "malware"),
        ("virustotal", "VirusTotal", "malware"),
        ("hybrid-analysis", "Hybrid Analysis", "malware"),
        
        // Mobile Forensics
        ("cellebrite", "Mobile forensics", "mobile"),
        ("oxygen", "Oxygen Forensics", "mobile"),
        ("andriller", "Android forensics", "mobile"),
        
        // Other Tools
        ("strings", "Extract strings", "utility"),
        ("binwalk", "Firmware analysis", "utility"),
        ("foremost", "File carving", "utility"),
        ("scalpel", "File carving", "utility"),
        ("bulk_extractor", "Bulk data extraction", "utility"),
    ]
}

pub fn get_vm_indicators() -> Vec<(&'static str, &'static str)> {
    vec![
        // VMware
        ("vmware", "VMware virtualization"),
        ("vmtoolsd", "VMware Tools daemon"),
        ("vmhgfs", "VMware HGFS"),
        ("vmmouse", "VMware mouse"),
        ("vmxnet", "VMware network"),
        
        // VirtualBox
        ("virtualbox", "VirtualBox"),
        ("vboxservice", "VirtualBox service"),
        ("vboxguest", "VirtualBox guest"),
        ("vboxtray", "VirtualBox tray"),
        
        // QEMU/KVM
        ("qemu", "QEMU emulator"),
        ("kvm", "KVM virtualization"),
        ("virtio", "VirtIO drivers"),
        
        // Hyper-V
        ("hyper-v", "Microsoft Hyper-V"),
        ("vmbus", "Hyper-V VMBus"),
        
        // Xen
        ("xen", "Xen hypervisor"),
        ("xenbus", "Xen bus"),
        
        // Parallels
        ("parallels", "Parallels Desktop"),
        ("prl_", "Parallels tools"),
    ]
}

pub fn get_sandbox_indicators() -> Vec<&'static str> {
    vec![
        // Cuckoo Sandbox
        "C:\\cuckoo",
        "C:\\analysis",
        "/tmp/cuckoo",
        
        // Joe Sandbox
        "C:\\joesandbox",
        "C:\\analysis",
        
        // Generic
        "C:\\sandbox",
        "C:\\malware",
        "/tmp/sandbox",
        "/tmp/malware",
        
        // Processes
        "agent.py",
        "analyzer.py",
        "sample.exe",
    ]
}
