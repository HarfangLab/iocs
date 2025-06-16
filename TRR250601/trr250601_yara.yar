rule XDSpy_LNK_2025 {
    meta:
        description = "Matches XDSpy malicious LNK files, used in 2025"
        references = "TRR250601"
        hash = "904db68a915b4bbd0b4b2d665bb1e2c51fa1b71b9c44ce45ccd4b4664f2bfd8e"
        hash = "536cd589cd685806b4348b9efa06843a90decae9f4135d1b11d8e74c7911f37d"
        hash = "0b705938e0063e73e03645e0c7a00f7c8d8533f1912eab5bf9ad7bc44d2cf9c3"
        date = "2025-05-16"
        author = "HarfangLab"
        context = "file"
    strings:
        $c1 = "/nologo /r:System.IO.Compression.FileSystem.dll /out:%TEMP%" wide fullword
        $c2 = "%SystemRoot%\\Microsoft.Net\\Framework\\*jsc.exe" wide fullword
        $c3 = "+Convert.ToChar(46)+Convert.ToChar(105)+Convert.ToChar(110)+Convert.ToChar(105)" wide fullword
    condition:
        (filesize > 1KB) and (filesize < 10KB)
        and (uint32(0) == 0x0000004C)
        and ((uint32be(4) == 0x01140200) and (uint32be(8) == 0x00000000) and (uint32be(12) == 0xC0000000) and (uint32be(16) == 0x00000046))
        and (uint8(0x14) & 0x20 == 0x20)
        and (uint8(0x14) & 0x80 == 0x80)
        and (any of ($c*))
}

rule XDSpy_ETDownloader {
    meta: 
        description = "Matches XDSpy 1st stage ET Downloader malware"
        hash = "792c5a2628ec1be86e38b0a73a44c1a9247572453555e7996bb9d0a58e37b62b"
        date = "2025-05-16"
        author = "HarfangLab"
        context = "file"
    strings:
        $dotNet = ".NETFramework,Version=" ascii
        $s1 = "$fcca44e8-9635-4cd7-974b-e86e6bce12cd" ascii fullword
        $s2 = "/startup" wide fullword
        $s3 = "ExportTests.dll" ascii wide fullword
        $s4 = "+<PayloadDownload>d__" ascii
        $s5 = "+<PayloadDownloadExecution>d__" ascii
        $f1 = "HttpWebResponse" ascii fullword
        $f2 = "set_UseShellExecute" ascii fullword
        $f3 = "set_CreateNoWindow" ascii fullword
        $f4 = "FromBase64String" ascii fullword
        $f5 = "set_ServerCertificateValidationCallback" ascii fullword
        $f6 = "AsyncTaskMethodBuilder" ascii fullword
        $f7 = "rangeDecoder" ascii fullword
        $f8 = "NumBitLevels" ascii fullword
        $f9 = "GetCallingAssembly" ascii fullword
        $f10 = "BlockCopy" ascii fullword
        $f11 = "MemoryStream" ascii fullword
    condition:
        uint16(0) == 0x5a4d and 
        filesize > 20KB and filesize < 120KB and
        $dotNet and
        (
            ( (2 of ($s*)) and (3 of ($f*)) )
            or ( all of ($f*) )
        )
}

rule XDSpy_XDigo {
    meta: 
        description = "Rule to catch XDSpy Main module, written in golang"
        hash = "49714e2a0eb4d16882654fd60304e6fa8bfcf9dbd9cd272df4e003f68c865341"
        hash = "0d983f5fb403b500ec48f13a951548d5a10572fde207cf3f976b9daefb660f7e"
        hash = "3adeda2a154dcf017ffed634fba593f80df496eb2be4bee0940767c8631be7c1"
        date = "2025-05-16"
        author = "HarfangLab"
        context = "file"
    strings:
        $a1 = "main.oooo_" ascii
        $b1 = "anti.go" ascii fullword
        $b2 = "crypto.go" ascii fullword
        $b3 = "file.go" ascii fullword
        $b4 = "main.go" ascii fullword
        $b5 = "net.go" ascii fullword
        $b6 = "log.go" ascii fullword
        $b7 = "settings.go" ascii fullword
        $b8 = "screenshot_windows.go" ascii fullword
        $c1 = "passwords.go" ascii fullword
        $c2 = "keylog.go" ascii fullword
    condition:
        uint16(0) == 0x5a4d and 
        filesize > 1MB and
        filesize < 15MB and
        #a1 > 100 and
        (any of ($c*) or all of ($b*)) 
}