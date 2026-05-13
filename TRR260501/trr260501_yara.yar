rule Gamaredon_GammaDrop {
    meta:
        description = "Matches Gamaredon GammaDrop VBScript samples used in late 2025 - mid 2026"
        references = "TRR260501"
        hash = "62818ae5e305b89b9461536dac1b9daf4cebd99d24e417357e27e2ae4582a704"
        date = "2026-05-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $vbs = "On Error Resume Next" ascii
        $a1 = "Function " ascii
        $a2 = "End Function" ascii
        $a3 = ".Run " ascii
        $a4 = "= Eval(" ascii
        $a5 = "randomize" ascii
        $a6 = "CreateObject(" ascii nocase
        $a7 = ", false" ascii

        $b1 = " + \"" ascii
    condition:
        filesize < 600KB
        and $vbs in (0..80)
        and #vbs >= 4
        and #a1 >= 2 and #a2 >= 2 and #a3 >= 1
        and 5 of ($a*)
        and #b1 > 150
}

rule Gamaredon_GammaLoad_HTA {
    meta:
        description = "Matches Gamaredon GammaLoad HTA wrapped VBScript samples used in late 2025 - mid 2026"
        references = "TRR260501"
        hash = "69cdde1ec82099a471283de89dd5e17266b1d8dda57d3c1589b7754b009fa2ed"
        date = "2026-05-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $hta = "<!DOCTYPE html>" ascii
        $vbs = "on error resume next" ascii nocase
        $a1 = "Function " ascii
        $a2 = "End Function" ascii nocase
        $a3 = "<script type=\"text/vbscript\">" ascii
        $a4 = "=\"ZGltIG" ascii
        $a5 = ".shellexecute " ascii
        $a6 = "%TEMP%" ascii
        $a7 = "\"REG_SZ\"" ascii
        $a8 = "Close" ascii fullword
        $a9 = ".createelement(" ascii
        $a10 = "\"utf-8\"" ascii

        $b1 = " + \"" ascii
    condition:
        filesize < 900KB
        and $hta
        and #vbs >= 5
        and #a1 >= 3 and #a2 >= 2
        and 4 of ($a*)
        and #b1 > 30
}

rule VBScript_RAR_CVE_2025_8088 {
    meta:
        description = "Matches RAR5 archives exploiting CVE-2025-8088 to drop VBScript into Startup folder, used by Gamaredon in late 2025 - mid 2026"
        reference = "TRR260501"
        hash = "00b8e381046d4e024a97d0402c3fe29f9d7f5114b2a932003d3e089cfdf992c1"
        date = "2026-05-13"
        author = "HarfangLab"
        context = "file"
    strings:
        $rar5_magic = { 52 61 72 21 1A 07 01 00 }

        // RAR5 Service Header (type 03) with STM (NTFS alternate data stream)
        // Header type 03, flags 23, followed by STM name and path traversal colon
        $stm_header = {
            03           // Header Type = Service Header
            23           // Header flags
            [17-20]      // Flags, sizes, extra data
            00           // Windows OS
            03           // Name length = 3
            53 54 4D     // "STM"
            [1-2]        // vint size of stream name
            07           // Data type = Service data
            3A           // Colon ":" starting ADS path
            2E 2E 5C    // "..\\" path traversal start
        }
        $startup_path = "AppData\\Roaming\\Microsoft\\Windows\\" ascii
        $startup_folder = "\\Startup\\" ascii
        $vbs = ".vbs" ascii
        $vbe = ".vbe" ascii
    condition:
        $rar5_magic at 0 
        and filesize < 700KB
        and $stm_header 
        and $startup_path 
        and $startup_folder 
        and any of ($vb*)
}