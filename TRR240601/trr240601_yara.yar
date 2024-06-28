rule Supposed_Grasshopper_Downloader 
{
    meta:
        description = "Detects the Nim downloader from the Supposed Grasshopper campaign."
        references = "TRR240601"
        date = "2024-06-20"
        author = "HarfangLab"
        context = "file,memory"
    strings:
        $pdb_path = "C:\\Users\\or\\Desktop\\nim-" ascii
        $code = "helo.nim" ascii
        $function_1 = "DownloadExecute" ascii fullword
        $function_2 = "toByteSeq" ascii fullword
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Donut_shellcode {
    meta:
        description = "Detects Donut shellcode in memory."
        references = "TRR240601"
        date = "2024-06-20"
        author = "HarfangLab"
        context = "memory"
    strings:
        // mov     rax, [rsp+arg_28] (or arg_20)
        // and     dword ptr [rax], 0
        // xor     eax, eax
        // retn
        $amsi_patch = { 48 8B 44 24 (28 | 30) 83 20 00 33 C0 C3 }
        // mov     dword ptr [r8], 1
        // xor     eax, eax
        // retn
        $wldp_patch = { 41 C7 00 01 00 00 00 33 C0 C3 }
        // mov     eax, edx
        // sror    ecx, 8
        // add     ecx, r8d
        // mov     edx, ebx
        // xor     ecx, r9d
        // ror     edx, 8
        // add     edx, r9d
        // rol     r8d, 3
        // xor     edx, r10d
        // rol     r9d, 3
        // xor     r9d, edx
        // xor     r8d, ecx
        // inc     r10d
        // mov     ebx, r11d
        // mov     r11d, eax
        // cmp     r10d, 1Bh
        $api_hashing = { 8B C2 C1 C9 08 41 03 C8 8B D3 41 33 C9 C1 CA 08 41 03 D1 41 C1 C0 03 41 33 D2 41 C1 C1 03 44 33 CA 44 33 C1 41 FF C2 41 8B DB 44 8B D8 41 83 FA 1B }
        $loaded_dlls = "ole32;oleaut32;wininet;mscoree;shell32" ascii
        $function_1 = "WldpQueryDynamicCodeTrust" ascii
        $function_2 = "WldpIsClassInApprovedList" ascii
        $function_3 = "AmsiInitialize" ascii
        $function_4 = "AmsiScanBuffer" ascii
        $function_5 = "AmsiScanString" ascii
    condition:
        // Shellcode starts with a "call"
        uint8(0) == 0xE8 and
        (
            // Find either all the patching/decoding code or the suspicious strings
            (#amsi_patch > 1 and $wldp_patch and $api_hashing) or
            ($loaded_dlls and all of ($function_*))
        )
}