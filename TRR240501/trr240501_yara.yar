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
