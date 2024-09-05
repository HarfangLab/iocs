rule masepie_campaign_htmlstarter
{
    meta:
        description = "Detect Malicious Web page HTML file from CERT-UA#8399"
        references = "TRR240101;https://cert.gov.ua/article/6276894"
        hash = "628bc9f4aa71a015ec415d5d7d8cb168359886a231e17ecac2e5664760ee8eba"
        date = "2024-01-24"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "<link rel=\"stylesheet\" href=\"a.css\">" ascii wide fullword
        $s2 = "src=\".\\Capture" ascii wide
    condition:
        filesize > 600 and filesize < 5KB
        and (all of them)
}
rule masepie_campaign_webdavlnk
{
    meta:
        description = "Detect Malicious LNK from CERT-UA#8399"
        references = "TRR240101;https://cert.gov.ua/article/6276894"
        hash = "19d0c55ac466e4188c4370e204808ca0bc02bba480ec641da8190cb8aee92bdc"
        date = "2024-01-24"
        author = "HarfangLab"
        context = "file"
    strings:
        $a1 = "[system.Diagnostics.Process]::Start('msedge','http" wide nocase fullword
        $a2 = "\\Microsoft\\Edge\\Application\\msedge.exe" wide nocase fullword
        $a3 = "powershell.exe" ascii wide fullword
        $s1 = "win-j5ggokh35ap" ascii fullword
        $s2 = "desktop-q0f4sik" ascii fullword
    condition:
        filesize > 1200 and filesize < 5KB
        and (uint16be(0) == 0x4c00)
        and (
            (all of ($a*))
            or (any of ($s*))
        )
}
rule masepie_campaign_masepie
{
    meta:
        description = "Detect MASEPIE from CERT-UA#8399"
        references = "TRR240101;https://cert.gov.ua/article/6276894"
        hash = "18f891a3737bb53cd1ab451e2140654a376a43b2d75f6695f3133d47a41952b6"
        date = "2024-01-24"
        author = "HarfangLab"
        context = "file"
    strings:
        $t1 = "Try it againg" ascii wide fullword
        $t2 = "{user}{SEPARATOR}{k}" ascii wide fullword
        $t3 = "Error transporting file" ascii wide fullword
        $t4 = "check-ok" ascii wide fullword
        $a1 = ".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))" ascii wide fullword
        $a2 = "dec_file_mes(mes, key)" ascii wide fullword
        $a3 = "os.popen('whoami').read()" ascii wide fullword
    condition:
        filesize > 2KB and filesize < 15MB
        and (4 of them)
}
rule masepie_campaign_oceanmap
{
    meta:
        description = "Detect OCEANMAP from CERT-UA#8399"
        references = "TRR240101;https://cert.gov.ua/article/6276894"
        hash = "24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04"
        date = "2024-01-24"
        modified = "2024-01-31"
        author = "HarfangLab"
        context = "file"
    strings:
        $dotNet = ".NETFramework,Version" ascii fullword
        $a1 = "$ SELECT INBOX.Drafts" wide fullword
        $a2 = "$ SELECT Drafts" wide fullword
        $a3 = "$ UID SEARCH subject \"" wide fullword
        $a4 = "$ APPEND INBOX {" wide fullword
        $a5 = "+FLAGS (\\Deleted)" wide fullword
        $a6 = "$ EXPUNGE" wide fullword
        $a7 = "BODY.PEEK[text]" wide fullword
        $t1 = "change_time" ascii fullword
        $t2 = "ReplaceBytes" ascii fullword
        $t3 = "fcreds" ascii fullword
        $t4 = "screds" ascii fullword
        $t5 = "r_creds" ascii fullword
        $t6 = "comp_id" ascii fullword
        $t7 = "changesecond" wide fullword
        $t8 = "taskkill /F /PID" wide fullword
        $t9 = "cmd.exe" wide fullword
    condition: 
        filesize > 8KB and filesize < 100KB
        and (uint16be(0) == 0x4D5A)
        and $dotNet
        and (3 of ($a*))
        and (2 of ($t*))
}
rule allasenhamaycampaign_executorloader {
    meta:
        description = "Detects Delphi ExecutorLoader DLLs and executables."
        references = "TRR240501"
        date = "2024-05-28"
        author = "HarfangLab"
        context = "file,memory"
    strings:
        $delphi = "Embarcadero Delphi" ascii fullword
        $s1 = "\\SysWOW64\\mshta.exe" wide fullword
        $s2 = "\\System32\\mshta.exe" wide fullword
        $s3 = "RcDll" wide fullword
        $default1 = "Default_" wide fullword
        $default2 = "Default~" wide fullword
    condition:
        $delphi
        and all of ($s*)
        and any of ($default*)
}
rule allasenhamaycampaign_allasenha {
    meta:
        description = "Detects AllaSenha banking trojan DLLs."
        references = "TRR240501"
        date = "2024-05-28"
        author = "HarfangLab"
        context = "file,memory"
    strings:
        $a1 = "<|NOSenha|>" wide fullword
        $a2 = "<|SENHA|>QrCode: " wide fullword
        $a3 = "<|SENHA|>Senha 6 : " wide fullword
        $a4 = "<|SENHA|>Snh: " wide fullword
        $a5 = "<|SENHA|>Token: " wide fullword
        $a6 = "<|BB-AMARELO|>" wide fullword
        $a7 = "<|BB-AZUL|>" wide fullword
        $a8 = "<|BB-PROCURADOR|>" wide fullword
        $a9 = "<|ITAU-SNH-CARTAO|>" wide fullword
        $a10 = "<|ITAU-TK-APP|>" wide fullword
        $dga = { 76 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 78 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 7A 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 77 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 6B 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 79 00 00 00 }
    condition:
        $dga
        and (4 of ($a*))
}
rule anti_emulation_defender {
    meta:
        description = "Research Windows Defender Emulator artefacts that can be used as anti-emulator by malware"
        references = "https://harfanglab.io/en/insidethelab/raspberry-robin-and-its-new-anti-emulation-trick/‎"
        hash = "242851abe09cc5075d2ffdb8e5eba2f7dcf22712625ec02744eecb52acd6b1bf"
        date = "2024-04-03"
        author = "Harfanglab"
        context = "file"
    strings:
        $s_00 = "aaa_TouchMeNot_" wide ascii nocase
        $s_01 = "_TouchMeNot_" wide ascii nocase
        $s_03 = "C:\\myapp.exe" wide ascii nocase
        $s_04 = "C:\\Mirc\\" wide ascii nocase
        $s_05 = "C:\\Mirc\\mirc.ini" wide ascii nocase
        $s_06 = "C:\\Mirc\\script.ini" wide ascii nocase
        $s_07 = "HAL9TH" wide ascii nocase fullword
        $s_09 = "MpSockVendor" wide ascii nocase fullword
        $s_10 = "MPGoodStatus" wide ascii nocase fullword
        $s_11 = "MpDisableSehLimit" wide ascii nocase fullword
        $s_12 = "NtControlChannel" wide ascii nocase fullword
        $s_13 = "ObjMgr_ValidateVFSHandle" wide ascii nocase fullword
        $s_14 = "ThrdMgr_GetCurrentThreadHandle" wide ascii nocase fullword
        $s_15 = "ThrdMgr_SaveTEB" wide ascii nocase fullword
        $s_16 = "ThrdMgr_SwitchThreads" wide ascii nocase fullword
        $s_17 = "VFS_DeleteFileByHandle" wide ascii nocase fullword
        $s_18 = "VFS_DeleteFile" wide ascii nocase fullword
        $s_19 = "VFS_DeleteFileByHandle" wide ascii nocase fullword
        $s_20 = "VFS_FileExists" wide ascii nocase fullword
        $s_21 = "VFS_FindClose" wide ascii nocase fullword
        $s_22 = "VFS_FindFirstFile" wide ascii nocase fullword
        $s_23 = "VFS_FindNextFile" wide ascii nocase fullword
        $s_24 = "VFS_FlushViewOfFile" wide ascii nocase fullword
        $s_25 = "VFS_GetAttrib" wide ascii nocase fullword
        $s_26 = "VFS_GetHandle" wide ascii nocase fullword
        $s_27 = "VFS_GetLength" wide ascii nocase fullword
        $s_28 = "VFS_MapViewOfFile" wide ascii nocase fullword
        $s_29 = "VFS_MoveFile" wide ascii nocase fullword
        $s_30 = "VFS_Open" wide ascii nocase fullword
        $s_31 = "VFS_Read" wide ascii nocase fullword
        $s_32 = "VFS_SetAttrib" wide ascii nocase fullword
        $s_33 = "VFS_SetCurrentDir" wide ascii nocase fullword
        $s_34 = "VFS_SetLength" wide ascii nocase fullword
        $s_35 = "VFS_UnmapViewOfFile" wide ascii nocase fullword
        $s_37 = "MpAddToScanQueue" wide ascii nocase fullword
        $s_38 = "MpCreateMemoryAliasing" wide ascii nocase fullword
        $s_39 = "MpCallPostEntryPointCode" wide ascii nocase fullword
        $s_40 = "MpCallPreEntryPointCode" wide ascii nocase fullword
        $s_41 = "MpDispatchException" wide ascii nocase fullword
        $s_42 = "MpExitThread" wide ascii nocase fullword
        $s_43 = "MpFinalize" wide ascii nocase fullword
        $s_44 = "MpGetCurrentThreadHandle" wide ascii nocase fullword
        $s_45 = "MpGetCurrentThreadId" wide ascii nocase fullword
        $s_46 = "MpGetLastSwitchResult" wide ascii nocase fullword
        $s_47 = "MpGetPseudoThreadHandle" wide ascii nocase fullword
        $s_48 = "MpGetSelectorBase" wide ascii nocase fullword
        $s_49 = "MpGetVStoreFileHandle" wide ascii nocase fullword
        $s_50 = "MpHandlerCodePost" wide ascii nocase fullword
        $s_51 = "MpIntHandler" wide ascii nocase fullword
        $s_52 = "MpIntHandlerParam" wide ascii nocase fullword
        $s_53 = "MpIntHandlerReturnAddress" wide ascii nocase fullword
        $s_54 = "MpNtdllDatatSection" wide ascii nocase fullword
        $s_55 = "MpReportEvent" wide ascii nocase fullword
        $s_56 = "MpReportEventEx" wide ascii nocase fullword
        $s_57 = "MpReportEventW" wide ascii nocase fullword
        $s_58 = "MpSehHandler" wide ascii nocase fullword
        $s_59 = "MpSetSelectorBase" wide ascii nocase fullword
        $s_60 = "MpStartProcess" wide ascii nocase fullword
        $s_61 = "MpSwitchToNextThread" wide ascii nocase fullword
        $s_62 = "MpSwitchToNextThread_WithCheck" wide ascii nocase fullword
        $s_63 = "MpSwitchToNextThread_NewObjManager" wide ascii nocase fullword
        $s_64 = "MpTimerEvent" wide ascii nocase fullword
        $s_65 = "MpTimerEventData" wide ascii nocase fullword
        $s_66 = "MpUfsMetadataOp" wide ascii nocase fullword
        $s_67 = "MpValidateVFSHandle" wide ascii nocase fullword
        $s_68 = "MpVmp32Entry" wide ascii nocase fullword
        $s_69 = "MpVmp32FastEnter" wide ascii nocase fullword
        $filter_00 = "mpengine.pdb" ascii nocase
        $filter_01 = "MsMpEngCP.pdb" ascii nocase
        $filter_02 = "MsMpEngSvc.pdb" ascii nocase
        $filter_03 = "MpGear.pdb" ascii nocase
        $filter_04 = "mrtstub.pdb" ascii nocase
        $filter_05 = "mrt.pdb" ascii nocase
        $filter_06 = "ntoskrnl.pdb" ascii nocase
        $filter_07 = "mscorlib.pdb" ascii nocase
        $filter_08 = "dbghelp.pdb" ascii nocase
        $filter_09 = "msvcrt.pdb" ascii nocase
        $filter_10 = "mrt.exe" wide ascii nocase
        $filter_11 = "PEBMPAT:Obfuscator_EW2" wide ascii
        $filter_12 = "Unimplemented type change to VT_" wide ascii
        $filter_13 = "Initialize engine first!" wide ascii
        $filter_14 = "VirTool:Win32/Obfuscator" wide ascii
        $filter_15 = "VDMConsoleOperation" wide ascii
        $filter_16 = "VDMOperationStarted" wide ascii
        $filter_17 = "sigutils\\vdlls\\" ascii
        $filter_18 = "Microsoft.Windows.MalwareRemovalTool" wide ascii
        $filter_19 = "AppVISVSubsystems32.pdb" ascii nocase
        $filter_20 = "Microsoft.AppV.ClientProgrammability.Eventing.pdb" ascii nocase
        $filter_21 = "AppVISVSubsystems64.pdb" ascii nocase
        $filter_22 = "AppVEntSubsystems.pdb" ascii nocase
        $filter_24 = "shell32.pdb" ascii nocase
        $filter_25 = "version.pdb" ascii nocase
        $filter_26 = "mscoree.pdb" ascii nocase
        $filter_27 = "ws2_32.pdb" ascii nocase
        $filter_28 = "advapi32.pdb" ascii nocase
        $filter_29 = "AppVEntSubsystems64.pdb" ascii nocase
        $filter_30 = "AppVEntSubsystems32.pdb" ascii nocase
        $filter_31 = "AppVISVSubsystems.pdb" ascii nocase
        $filter_32 = "mpengine.dll" ascii wide nocase
        $filter_33 = "VFSAPI_VFS_" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 5MB
        and 1 of ($s_*)
        and not 1 of ($filter*)
}
rule charmingkitten_cyclops
{
    meta:
        description = "Detects Cyclops Golang Malware"
        references = "TRR240801"
        hash = "fafa68e626f1b789261c4dd7fae692756cf71881c7273260af26ca051a094a69"
        date = "2024-08-05"
        author = "HarfangLab"
        context = "file"
    strings:
        $go = " Go build ID: \"" ascii
        $a1 = "dep\tback-service\t(devel)" ascii fullword
        $a2 = "/brain-loader-enc.go\x00" ascii
        $a3 = "back-service/go-mux/api" ascii
        $a4 = "/JD-M42KItJncJfqb38qh/" ascii
    condition:
        filesize > 2MB and filesize < 20MB
        and (uint16(0) == 0x5A4D)
        and $go
        and (2 of ($a*))
}
rule samecoin_campaign_loader {
    meta:
        description = "Matches the loader used in the SameCoin campaign"
        references = "TRR240201"
        hash = "cff976d15ba6c14c501150c63b69e6c06971c07f8fa048a9974ecf68ab88a5b6"
        date = "2024-02-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $hebrew_layout = "0000040d" fullword ascii
        $runas = "runas" fullword ascii
        $jpg_magic = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
        $wl_1 = "C:\\Users\\Public\\Microsoft Connection Agent.jpg" ascii
        $wl_2 = "C:\\Users\\Public\\Video.mp4" ascii
        $wl_3 = "C:\\Users\\Public\\Microsoft System Agent.exe" ascii
        $wl_4 = "C:\\Users\\Public\\Microsoft System Manager.exe" ascii
        $wl_5 = "C:\\Users\\Public\\Windows Defender Agent.exe"
    condition:
        uint16(0) == 0x5A4D and filesize > 5MB and filesize < 7MB and
        $hebrew_layout and $runas and $jpg_magic and 3 of ($wl_*)
}
rule samecoin_campaign_wiper {
    meta:
        description = "Matches the wiper used in the SameCoin campaign"
        references = "TRR240201"
        hash = "e6d2f43622e3ecdce80939eec9fffb47e6eb7fc0b9aa036e9e4e07d7360f2b89"
        date = "2024-02-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $code = { 68 57 04 00 00 50 E8 } // push 1111; push eax; call
        $wl_1 = "C:\\Users\\Public\\Microsoft Connection Agent.jpg" ascii
        $wl_2 = "C:\\Users\\Public\\Video.mp4" ascii
        $wl_3 = "C:\\Users\\Public\\Microsoft System Agent.exe" ascii
        $wl_4 = "C:\\Users\\Public\\Microsoft System Manager.exe" ascii
        $wl_5 = "C:\\Users\\Public\\Windows Defender Agent.exe" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        $code and 3 of ($wl_*)
}
rule samecoin_campaign_tasksspreader
{
    meta:
        description = "Detect .NET Task Scheduler that is dropper by SameCoin Loader"
        references = "TRR240201"
        hash = "b447ba4370d9becef9ad084e7cdf8e1395bafde1d15e82e23ca1b9808fef13a7"
        date = "2024-02-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $dotNet = ".NETFramework,Version" ascii fullword
        $a1 = "System.DirectoryServices.ActiveDirectory" ascii fullword
        $a2 = "GetTypeFromProgID" ascii fullword
        $a3 = "DirectorySearcher" ascii fullword
        $a4 = "SearchResultCollection" ascii fullword
        $a5 = "UnaryOperation" ascii fullword
        $b1 = "$dc1b29f0-9a87-4383-ad8b-01285614def1" ascii fullword
        $b2 = "Windows Defender Agent" ascii fullword
        $b3 = "Windows Defender Agent.exe" wide ascii fullword
        $b4 = /(\\)?C(:|\$)\\Users\\Public\\Microsoft System Agent\.exe/ wide fullword
        $b5 = "MicrosoftEdgeUpdateTaskMachinesCores" wide fullword
        $b6 = "WindowsUpdate" wide fullword
        $c1 = "RegisterTaskDefinition" wide fullword
        $c2 = "DisallowStartIfOnBatteries" wide fullword
        $c3 = "StopIfGoingOnBatteries" wide fullword
        $c4 = "Schedule.Service" wide fullword
        $c5 = "\\Domain Users" wide fullword
        $c6 = "(objectClass=computer)" wide fullword
    condition: 
        filesize > 8KB and filesize < 40KB
        and (uint16be(0) == 0x4D5A)
        and $dotNet
        and (4 of ($a*))
        and (
            ((any of ($b*)) and (any of ($c*)))
            or (all of ($c*))
        )
}
rule samecoin_campaign_nativewiper {
    meta:
        author = "HarfangLab"
        description = "Matches the native Android library used in the SameCoin campaign"
        references = "TRR240201"
        hash = "248054658277e6971eb0b29e2f44d7c3c8d7c5abc7eafd16a3df6c4ca555e817"
        last_modified = "2024-02-13"
        context = "file"
    strings:
        $native_export = "Java_com_example_exampleone_MainActivity_deleteInCHunks" ascii
        $f1 = "_Z9chunkMainv" ascii
        $f2 = "_Z18deleteFilesInChunkRKNSt6__" ascii
        $f3 = "_Z18overwriteWithZerosPKc" ascii
        $s1 = "/storage/emulated/0/" ascii
        $s2 = "FileLister" ascii
        $s3 = "Directory chunks deleted."
        $s4 = "Current Chunk Size is:  %dl\n" ascii
    condition:
        filesize < 500KB and uint32(0) == 0x464C457F and
        ($native_export or all of ($f*) or all of ($s*))
}
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
rule MuddyWater_AteraAgent_Operators {
    meta:
        description = "Detect Atera Agent abused by MuddyWater"
        references = "TRR240402"
        hash = "9b49d6640f5f0f1d68f649252a96052f1d2e0822feadd7ebe3ab6a3cadd75985"
        date = "2024-04-17"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "COMPANYID001Q3000009snPyIAIACCOUNTID"
        $s2 = "COMPANYID001Q3000006FpmoIACACCOUNTID" 
        $s3 = "COMPANYID001Q3000008IyacIACACCOUNTID"
        $s4 = "COMPANYID001Q3000009QoSEIA0ACCOUNTID"
        $s5 = "COMPANYID001Q30000023c7iIAAACCOUNTID"
        $s6 = "COMPANYID001Q3000008qXbDIAUACCOUNTID"
        $s7 = "COMPANYID001Q3000008cfLjIAIACCOUNTID"
        $s8 = "COMPANYID001Q3000007hJubIAEACCOUNTID"
        $s9 = "COMPANYID001Q3000008ryO3IAIACCOUNTID"
        $s10 = "COMPANYID001Q300000A5nnAIARACCOUNTID"
        $s11 = "COMPANYID001Q3000008JfioIACACCOUNTID"
        $s12 = "COMPANYID001Q300000BeUp3IAFACCOUNTID" 
        $s13 = "COMPANYID001Q3000005gMamIAEACCOUNTID"
        $s15 = "mrrobertcornish@gmail.comINTEGRATORLOGINCOMPANYID"
        $cert1 = { 0A 28 49 99 78 E5 89 8D F4 0A 23 8E B8 A5 52 E8 } // Atera Network certificate 2024-02-15 - 2025-03-18
        $cert2 = { 06 7F 60 47 95 66 24 A7 15 99 61 74 3D 81 94 93 } // Atera Network certificate 2022-02-17 - 2024-03-16
    condition: 
        filesize > 1MB and filesize < 4MB
        and (uint16be(0) == 0xD0CF)
        and any of ($s*)
        and any of ($cert*)
}
rule apt31_rawdoor_dropper 
{ 
    meta: 
        description = "Matches the RawDoor dropper" 
        references = "TRR240401" 
        hash = "c3056e39f894ff73bba528faac04a1fc86deeec57641ad882000d7d40e5874be" 
        date = "2024-04-12" 
        author = "HarfangLab" 
        context = "file" 
    strings: 
        $service_target = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii 
        $service_dispname = "Microsoft .NET Framework NGEN" ascii 
        $drop_name = "~DF313.msi" ascii 
        $msg1 = "RegOpenKeyEx %s  error:%d\x0D\x0A" ascii 
        $msg2 = "RegDeleteValue Wow64 . %d\x0D\x0A" ascii 
        $msg3 = "CreateService %s success! but Start Faile.. %d\x0D\x0A" ascii 
        $msg4 = "OutResFile to %s%s False!" ascii 
        $msg5 = "Can't GetNetSvcs Buffer!" ascii 
    condition: 
        uint16(0) == 0x5A4D and filesize > 350KB and filesize < 600KB and 
        (($service_target and $service_dispname and $drop_name) or 3 of ($msg*)) 
}
rule apt31_rawdoor_payload 
{ 
    meta: 
        description = "Matches the RawDoor payload" 
        references = "TRR240401" 
        hash = "fade96ec359474962f2167744ca8c55ab4e6d0700faa142b3d95ec3f4765023b" 
        date = "2024-04-12" 
        author = "HarfangLab" 
        context = "file" 
    strings: 
        $name = "\x0D\x0A=================RawDoor %g================\x0D\x0A" ascii 
        $key = /SOFTWARE\\Clients\\Netra(u|w)/ ascii 
        $cmd1 = "Shell <powershell.exe path>" ascii 
        $cmd2 = "Selfcmd <self cmd string>" ascii 
        $cmd3 = "Wsrun <process name>" ascii 
        $cmd4 = "ping 127.0.0.1 > nul\x0D\x0A" 
        $cmd5 = "/c netsh advfirewall firewall add rule name=" ascii 
        $msg1 = "Allocate pSd memory to failed!" ascii 
        $msg2 = "Allocate SID or ACL to failed!" ascii 
        $msg3 = "OpenSCManager error:%d" ascii 
        $msg4 = "%u:TCP:*:Enabled:%u" ascii 
    condition: 
        uint16(0) == 0x5A4D and filesize < 200KB and 
        (($name and $key) or (3 of ($cmd*) and 3 of ($msg*))) 
}
rule PackXOR
{
    meta:
        description = "Detection rule for PackXOR"
        references = "https://harfanglab.io/insidethelab/unpacking-packxor/"
        hash = "0506372e2c2b6646c539ac5a08265dd66d0da58a25545e444c25b9a02f8d9a44"
        date = "2024-08-05"
        author = "Harfanglab"
        context = "file"
    strings:
        $s_packer_xor = {
            4? 63 [3]                       // movsxd  rax, dword [rsp+0x50 {var_78}]
            4? 8b [2-6]                     // mov     rcx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rcx, qword [rcx+0x8]
            4? 0? [2]                       // add     rax, qword [rcx+0x50]
            4? 8d [5]                       // lea     rcx, [rel data_140003020]
            0f (b6|b7) [1-5]                // movzx   eax, byte [rcx+rax]
            0f (b6|b7) [1-5]                // movzx   ecx, byte [rel data_14002399c]
            4? 8b [2-6]                     // mov     rdx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rdx, qword [rdx+0x8]
            4? 0? [2]                       // add     rcx, qword [rdx+0x68]
            0f (b6|b7) [1-5]                // movzx   ecx, cl
            33 ??                           // xor     eax, ecx
            4? 63 [3]                       // movsxd  rcx, dword [rsp+0x50 {var_78}]
            4? 8b [2-6]                     // mov     rdx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rdx, qword [rdx+0x8]
            4? 0? [2]                       // add     rcx, qword [rdx+0x48]
            4? 8d [5]                       // lea     rdx, [rel data_140003020]
            88 04 0a                        // mov     byte [rdx+rcx], al
            0f (b6|b7)                      // movzx   eax, byte [rel data_14000301e]
        }
        $s_packer_decrypt_conf = {
            8b [1-3]            // mov     eax, dword [rsp+0x4 {i}]
            ff ??               // inc     eax
            89 [1-3]            // mov     dword [rsp+0x4 {i}], eax
            0f b6 [1-3]         // movzx   eax, byte [rsp {var_128}]
            39 [1-3]            // cmp     dword [rsp+0x4 {i}], eax
            73 ??               // jae     0x140001d59
            8b [1-3]            // mov     eax, dword [rsp+0x4 {i}]
            83 ?? 05            // add     eax, 0x5
            8b ??               // mov     eax, eax
            4? 8b [2-6]         // mov     rcx, qword [rsp+0x130 {arg_8}]
            0f be [1-3]         // movsx   eax, byte [rcx+rax]
            85 ??               // test    eax, eax
            74 ??               // je      0x140001d40
            0f b6 [1-3]         // movzx   eax, byte [rsp+0x2 {var_126}]
            8b [3]              // mov     ecx, dword [rsp+0x4 {i}]
            83 ?? 05            // add     ecx, 0x5
            8b ??               // mov     ecx, ecx
            4? 8b [4-6]         // mov     rdx, qword [rsp+0x130 {arg_8}]
            0f (be|bf) [1-3]    // movsx   ecx, byte [rdx+rcx]
            33 ??               // xor     eax, ecx
            2b [1-3]            // sub     eax, dword [rsp+0x4 {i}]
            ff ??               // dec     eax
            8b [1-3]            // mov     ecx, dword [rsp+0x4 {i}]
            88 [1-3]            // mov     byte [rsp+rcx+0x20 {var_108}], al
            eb ??               // jmp     0x140001d57
            b8 01 00 00 00      // mov     eax, 0x1
            4? 6b ?? 00         // imul    rax, rax, 0x0
            4? 8b [4-6]         // mov     rcx, qword [rsp+0x130 {arg_8}]
            c6 [1-3] 00         // mov     byte [rcx+rax], 0x0
            eb ??               // jmp     0x140001d59
            eb                  // jmp     0x140001ce7
        }
        $s_packer_find_entry_point = {
            4? 63 [1-4]             // movsxd  rax, dword [rsp {var_38_1}]
            4? 3b [1-4]             // cmp     rax, qword [rsp+0x20 {var_18_1}]
            73 ??                   // jae     0x140001c7f
            48 8b [1-4]             // mov     rax, qword [rsp+0x10 {var_28_1}]
            0f b7 [1-4]             // movzx   eax, word [rax]
            c1 ?? 0c                // sar     eax, 0xc
            83 ?? 0a                // cmp     eax, 0xa
            75 ??                   // jne     0x140001c7d
            4? 8b [1-4]             // mov     rax, qword [rsp+0x8 {var_30}]
            8b [1-4]                // mov     eax, dword [rax]
            4? 03 [1-4]             // add     rax, qword [rsp+0x40 {arg_8}]
            4? 8b [1-4]             // mov     rcx, qword [rsp+0x10 {var_28_1}]
            0f b7 [1-4]             // movzx   ecx, word [rcx]
            81 ?? ff 0f 00 00       // and     ecx, 0xfff
            4? 63 [1-4]             // movsxd  rcx, ecx
            4? 03 [1-4]             // add     rax, rcx
            4? 89 [1-4]             // mov     qword [rsp+0x18 {var_20_1}], rax
            4? 8b [1-4]             // mov     rax, qword [rsp+0x18 {var_20_1}]
            4? 8b [1-4]             // mov     rax, qword [rax]
            4? 03 [1-4]             // add     rax, qword [rsp+0x50 {arg_18}]
            4? 8b [1-4]             // mov     rcx, qword [rsp+0x18 {var_20_1}]
            4? 89 [1-4]             // mov     qword [rcx], rax
            eb 93                   // jmp     0x140001c12
        }
        $s_packer_find_entry_point_rtlcreateuserthtread = {
            4? 8b [1-4]                // mov     rax, qword [rsp+0x70 {var_58_1}]
            8b [1-4]                   // mov     eax, dword [rax+0x28]
            4? 03 [1-4]                // add     rax, qword [rsp+0x68 {var_60_1}]
            4? 89 [2-6]                // mov     qword [rsp+0x88 {var_40_1}], rax
            ff [2-6]                   // call    qword [rsp+0x88 {var_40_1}]
            4? 8d [2-6]                // lea     rax, [rsp+0x9c {var_2c}]
            4? 89 [1-4]                // mov     qword [rsp+0x48 {var_80_1}], rax {var_2c}
            4? 8d [2-6]                // lea     rax, [rsp+0xb8 {var_10}]
            4? 89 [1-4]                // mov     qword [rsp+0x40 {var_88_1}], rax {var_10}
            4? c7 [3-7]                // mov     qword [rsp+0x38 {var_90}], 0x0
            4? 8b [2-6]                // mov     rax, qword [rsp+0x88 {var_40_1}]
            4? 89 [1-4]                // mov     qword [rsp+0x30 {var_98_1}], rax
            4? c7 [3-7]                // mov     qword [rsp+0x28 {var_a0}], 0x0
            4? c7 [3-7 ]               // mov     qword [rsp+0x20 {var_a8}], 0x0
            4? 33 ??                   // xor     r9d, r9d  {0x0}
            4? ?? 01                   // mov     r8b, 0x1
            33 ??                      // xor     edx, edx  {0x0}
            4? c? ?? ff ff ff ff       // mov     rcx, 0xffffffffffffffff
            ff                         // call    qword [rsp+0xa0 {var_28_1}]
        }
        $s_packer_string_encryption = {
            0f B? [1-2]      // movzx   eax, [rsp+128h+size_string]
            39 [1-3]         // cmp     [rsp+128h+var_124], eax
            73 ??            // jnb     short loc_140001CC9
            8B [1-3]         // mov     eax, [rsp+128h+var_124]
            83 ?? 05         // add     eax, 5
            8B ??            // mov     eax, eax
            4? 8B [1-6]      // mov     rcx, [rsp+128h+arg_0]
            0F B? [1-2]      // movsx   eax, byte ptr [rcx+rax]
            85 ??            // test    eax, eax
            74 ??            // jz      short loc_140001CB0
            0f B? [1-3]      // movzx   eax, [rsp+128h+key]
            8B [1-3]         // mov     ecx, [rsp+128h+var_124]
            83 ?? 05         // add     ecx, 5
            8B ??            // mov     ecx, ecx
            4? 8B [1-6]      // mov     rdx, [rsp+128h+arg_0]
            0F B? [1-2]      // movsx   ecx, byte ptr [rdx+rcx]
            33 ??            // xor     eax, ecx
            2B [1-3]         // sub     eax, [rsp+128h+var_124]
            FF ??            // dec     eax
            8B [1-3]         // mov     ecx, [rsp+128h+var_124]
            88 [1-3]         // mov     [rsp+rcx+128h+decrypted_string], al
            EB               // jmp     short loc_140001CC7
        }
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 20MB
        and 2 of ($s_packer*)
}
