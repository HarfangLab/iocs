rule trr250801_csharp_downloader_combined {
    meta:
        description = "Detects C# downloaders as likely leveraged by UNC1151, and observed between May and July 2025"
        references = "TRR250801"
        hash = "559ee2fad8d16ecaa7be398022aa7aa1adbd8f8f882a34d934be9f90f6dcb90b"
        hash = "a2a2f0281eed6ec758130d2f2b2b5d4f578ac90605f7e16a07428316c9f6424e"
        date = "2025-08-08"
        author = "HarfangLab"
        context = "file"
    strings:
        $dotNet = ".NETFramework,Version=" ascii
        $a1 = "set_SecurityProtocol" ascii fullword
        $a2 = "SecurityProtocolType" ascii fullword
        $a3 = "ManagementObjectSearcher" ascii fullword
        $a4 = "WebClient" ascii fullword
        $a5 = "DownloadString" ascii fullword
        $a6 = "get_Headers" ascii fullword
        $a7 = "StringBuilder" ascii fullword
        $a8 = "kernel32.dll" ascii fullword
        $a9 = "VirtualProtect" ascii fullword
        $a10 = "GetHINSTANCE" ascii fullword
        $a11 = "get_FullyQualifiedName" ascii fullword
        $a12 = "Marshal" ascii fullword
        $a13 = "get_OSVersion" ascii fullword
        $a14 = "get_MachineName" ascii fullword
        $a15 = "CreateDirectory" ascii fullword
        $a16 = "ToBase64String" ascii fullword
        $a17 = { 00 20C03F0000 28 } // nop, ldc.i4 0x00003FC0, call (TLS config)
    condition:
        filesize < 100KB and filesize > 10KB
        and (uint16be(0) == 0x4D5A)
        and $dotNet
        and (all of ($a*))
}

rule trr250801_cpp_downloader {
    meta:
        description = "Detects C++ downloaders as likely leveraged by UNC1151, and observed during May 2025"
        references = "TRR250801"
        hash = "5fa19aa32776b6ab45a99a851746fbe189f7a668daf82f3965225c1a2f8b9d36"
        date = "2025-08-08"
        author = "HarfangLab"
        context = "file"
    strings:
        $u = { 00 60 be 00 ?? ?? 00 8d be 00 ?? ?? ff 57 83 cd ff eb 10 90 90 90 90 90 90 8a 06 46 88 07 47 01 db 75 07 8b 1e 83 ee fc 11 db } // UPX decompression stub
        $s0 = "RTW0" fullword
        $s1 = "RTW1" fullword
        $s2 = "RTW2" fullword
        $e = "Start" fullword
    condition:
        filesize < 1MB and filesize > 10KB
        and (uint16be(0) == 0x4D5A)
        and $u
        and (2 of ($s*))
        and $e
}