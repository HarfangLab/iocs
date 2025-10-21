rule iis_module_hijackserver_native {
    meta:
        description = "Matches the IIS HijackServer module"
        references = "TRR251001"
        hash = "c1ca053e3c346513bac332b5740848ed9c496895201abc734f2de131ec1b9fb2"
        date = "2025-08-25"
        author = "HarfangLab"
        context = "file"
    strings:
        $c1 = ".?AVCHttpModule@@" ascii fullword
        $c2 = ".?AVCGlobalModule@@" ascii fullword
        $m1 = "RegisterModule" ascii fullword
        $s1 = "hack1234" ascii
        $s2 = "<!- GP -->" ascii fullword
        $s3 = /\.cseo\d{1,3}\.com\/config\// ascii
        $s4 = ":(80|443)(?=/|$)" ascii fullword
        $s5 = "TryCleanTmp:" ascii
        $s6 = "no excute " ascii
        $s7 = "\\b(\\d{1,2})-(\\d{1,2})-(\\d{4})\\b" ascii fullword
        $s8 = "/Tqpn0tGX550fVwt5D6g4CGWP6" ascii
        $s9 = "\\IISCPP-GM\\" ascii
        $s10 = "\\Dongtai.pdb\x00" ascii
        $s11 = "_FAB234CD3-09434-88" ascii
        $s12 = "<input type='text' name='cmdml' place" ascii
        $s13 = ".?AVHiJackServer@@" ascii fullword
        $s14 = ".?AVWebdllServer@@" ascii fullword
        $s15 = ".?AVAffLinkServer@@" ascii fullword
    condition:
        uint16be(0) == 0x4D5A
        and filesize > 200KB and filesize < 2MB
        and $m1
        and (any of ($c*))
        and (4 of ($s*))
}

rule iis_module_hijackserver_dotnet {
    meta:
        description = "Matches the IIS HijackServer .NET module"
        references = "TRR251001"
        hash = "915441b7d7ddb7d885ecfe75b11eed512079b49875fc288cd65b023ce1e05964"
        date = "2025-10-14"
        author = "HarfangLab"
        context = "file"
    strings:
        $dotNet = ".NETFramework,Version=" ascii
        $c1 = "HttpApplication" ascii fullword
        $c2 = "IHttpModule" ascii fullword
        $s1 = "YourSecretKey123" wide fullword
        $s2 = "<!- GP -->" wide fullword
        $s3 = /\.cseo\d{1,3}\.com\/config\// wide
        $s4 = ":(80|443)(?=/|$)" wide fullword
        $s5 = "clean?type=all" wide fullword
        $s6 = "DealRequest" ascii
        $s7 = "\\Tiquan\\CustomIISModule\\" ascii
        $s8 = "\\CustomIISModule.pdb\x00" ascii
        $s9 = "\\Temp\\AcpLogs\\conf\\" wide
        $s10 = "RobotTxtServer" ascii fullword
        $s11 = "HijackServer" ascii fullword
        $s12 = "WebdllServer" ascii fullword
        $s13 = "AffLinkServer" ascii fullword
    condition:
        uint16be(0) == 0x4D5A
        and filesize > 200KB and filesize < 2MB
        and $dotNet
        and (all of ($c*))
        and (4 of ($s*))
}

rule apache_module_hijackserver_php_decoded {
    meta:
        description = "Matches the decompressed and decoded Apache HijackServer PHP module"
        references = "TRR251001"
        hash = "e107bf25abc1cff515b816a5d75530ed4d351fa889078e547d7381b475fe2850"
        date = "2025-10-15"
        author = "HarfangLab"
        context = "file"
    strings:
        $php = /\$_SERVER\[\s*['"]PHP_SELF['"]\s*\]/ ascii wide fullword
        $s1 = "hj_clean_cache_dir" ascii wide fullword
        $s2 = "hj_get_file_content" ascii wide fullword
        $s3 = "\"清理目录空间 目录:\"" ascii wide fullword
        $s4 = "'/:(80|443)$/'" ascii wide fullword
        $s5 = "isCleanRequest()" ascii wide fullword
        $s6 = "shuffle_file_current_line" ascii wide fullword
        $s7 = "self::replaceAffLinkUrl" ascii wide fullword
        $s8 = "/Tqpn0tGX550fVwt5D6g4CGWP6" ascii wide
        $s9 = "HJ_CONFIG_URL_FORMAT" ascii wide fullword
        $s10 = "HJ_DEFAULT_LOCAL_LINK_NUM" ascii wide fullword
        $s11 = "renderHealthCheck" ascii wide fullword
        $s12 = "renderRedirect" ascii wide fullword
        $s13 = "renderAffLink" ascii wide fullword
    condition:
        filesize > 50KB and filesize < 600KB
        and $php
        and (4 of ($s*))
}

rule apache_module_hijackserver_php {
    meta:
        description = "Matches the encoded Apache HijackServer PHP module"
        references = "TRR251001"
        hash = "e107bf25abc1cff515b816a5d75530ed4d351fa889078e547d7381b475fe2850"
        date = "2025-10-15"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "\"display_errors\"" ascii wide fullword
        $s2 = /\$code\s*=\s*['"]eJztvWl7XMXRMPydX3GsKJmRGS22sQF5IbIkYwVZ/ ascii wide
        $s3 = /eval\(\s*gzuncompress\(\s*base64_decode\(\s*\$code\s*\)\s*\)\s*\);/ ascii wide nocase fullword
    condition:
        filesize > 10KB and filesize < 200KB
        and (all of them)
}

rule wingtb_rootkit {
    meta:
        description = "Matches the customized Hidden rootkit, Wingtb.sys."
        references = "TRR251001"
        hash = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"
        hash = "88fd3c428493d5f7d47a468df985c5010c02d71c647ff5474214a8f03d213268"
        date = "2025-10-15"
        author = "HarfangLab"
        context = "file"
    strings:
        $a1 = "\\Device\\WinkbjDamen" wide fullword
        $a2 = "\\DosDevices\\WinkbjDamen" wide fullword
        $s1 = "Kbj_Zhuangtai" wide fullword
        $s2 = "Kbj_YinshenMode" wide fullword
        $s3 = "Kbj_WinkbjFsDirs" wide fullword
        $s4 = "Kbj_WinkbjFsFiles" wide fullword
        $s5 = "Kbj_WinkbjRegKeys" wide fullword
        $s6 = "Kbj_WinkbjRegValues" wide fullword
        $s7 = "Kbj_FangxingImages" wide fullword
        $s8 = "Kbj_BaohuImages" wide fullword
        $s9 = "Kbj_WinkbjImages" wide fullword

        $pdb = "D:\\DriverSpace\\hidden\\x64\\Release\\Winkbj.pdb" fullword

    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        ((1 of ($a*) and 6 of ($s*)) or $pdb)
}

rule wingtb_rootkit_commandline_tool_wingtbcli {
    meta:
        description = "Matches the usermode command-line tool for rootkit, WingtbCLI.exe."
        references = "TRR251001"
        hash = "913431f1d36ee843886bb052bfc89c0e5db903c673b5e6894c49aabc19f1e2fc"
        date = "2025-10-15"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = ".?AVCommandUnignore@@" fullword
        $s2 = ".?AVCommandUnprotect@@" fullword
        $s3 = ".?AVCommandYinshen@@" fullword
        $s4 = "System\\CurrentControlSet\\Services\\Wingtb" wide fullword
        $s5 = "/buxiaoshi" wide fullword
        $s6 = "/fangxing" wide fullword
        $s7 = "/bufangxing" wide fullword
        $s8 = "/bubaohu" wide fullword
        $s9 = "/zhuangtai" wide fullword
        $s10 = "/yinshen" wide fullword
        $s11 = "Kbj_ShanchuFile" wide fullword
        $s12 = "Kbj_ShanchuDir" wide fullword
        $s13 = "Kbj_WinkbjRegValues" wide fullword
        $s14 = "Kbj_FangxingImages" wide fullword
        $s15 = "Kbj_Zhuangtai" wide fullword
        $s16 = "\\\\.\\WinkbjDamen" wide fullword
        $pdb = "D:\\DriverSpace\\hidden\\x64\\Release\\HiddenCLI.pdb" fullword
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        (8 of ($s*) or $pdb)
}
