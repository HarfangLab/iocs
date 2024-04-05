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