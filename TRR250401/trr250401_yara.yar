rule Gamaredon_PteroLNK_VBScript {
    meta:
        description = "Matches Gamaredon PteroLNK VBScript samples used in late 2024 to early 2025"
        references = "TRR250401"
        hash = "d5538812b9a41b90fb9e7d83f2970f947b1e92cb68085e6d896b97ce8ebff705"
        date = "2025-04-04"
        author = "HarfangLab"
        context = "file"
    strings:
        $vbs = "on error resume next" ascii wide
        $a1 = "=\"b24gZXJyb3IgcmVzdW1lIG5leHQNC" ascii wide
        $b1 = "\"\"%PUBLIC%\"\"" ascii wide 
        $b2 = "\"\"%APPDATA%\"\"" ascii wide
        $b3 = "\"\"REG_DWORD\"\"" ascii wide
    condition:
        filesize < 400KB
        and $vbs in (0..2)
        and $a1
        and 1 of ($b*)
}

rule Gamaredon_PteroLNK_LNK {
    meta:
        description = "Matches Gamaredon PteroLNK-generated LNK files used in late 2024 to early 2025"
        references = "TRR250401"
        hash = "N/A"
        date = "2025-04-04"
        author = "HarfangLab"
        context = "file"
    strings:
        $a1 = "javascript:eval('w=new%20ActiveXObject(\\\"\"WScript.Shell\\\"\");w.run(\\\"\"wscript.exe //e:vb\"\"+\"\"Script" ascii wide // Non-existing file lnk
        $a2 = "javascript:eval('w=new%20ActiveXObject(\\\"\"WScript.Shell\\\"\");w.run(\\\"\"explorer" ascii wide // Existing file/folder lnk
        $b1 = "\"\");window.close()')" ascii wide nocase
    condition:
        filesize < 10KB
        and uint32(0) == 0x0000004C // Standard LNK signature
        and uint32(4) == 0x00021401 // Expected values for LNK header
        and 1 of ($a*)
        and $b1
}