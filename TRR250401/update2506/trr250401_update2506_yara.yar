rule Gamaredon_PteroLNK_VBScript_update2506 {
    meta:
        description = "Matches Gamaredon PteroLNK VBScript samples used in 2025"
        references = "TRR250401;TRR250401_update2506"
        hash = "d5538812b9a41b90fb9e7d83f2970f947b1e92cb68085e6d896b97ce8ebff705"
        hash = "4787fe23a4ba66137e41d6caa877251092a7f4957ccd89ed374b71aa6f6e2037"
        date = "2025-06-23"
        author = "HarfangLab"
        context = "file"
    strings:
        $vbs = "on error resume next" ascii wide
        $a1 = "b24gZXJyb3IgcmVzdW1lIG5leHQNC" ascii wide
        $b1 = "\"\"%PUBLIC%\"\"" ascii wide 
        $b2 = "\"\"%APPDATA%\"\"" ascii wide
        $b3 = "\"\"REG_DWORD\"\"" ascii wide
        $b4 = "\"\"%USERPROFILE%\"\"" ascii wide
        $c1 = "\"\":SRV\"\"" ascii wide
        $c2 = "\"\":GTR\"\"" ascii wide
        $c3 = "\"\":LNK\"\"" ascii wide
        $c4 = "\"\":URLS\"\"" ascii wide
        $c5 = "\"\":IPS\"\"" ascii wide
    condition:
        filesize < 600KB
        and $vbs in (0..500)
        and $a1
        and (any of ($b*) or any of ($c*))
}
