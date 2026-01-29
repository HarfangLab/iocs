rule trr260101_sloppymio {
    meta:
        description = "Detects SloppyMIO, a C# implant leveraged by an Iranian threat actor in January 2026."
        references = "TRR260101"
        hash = "6d474cf5aeb58a60f2f7c4d47143cc5a11a5c7f17a6b43263723d337231c3d60"
        date = "2026-01-28"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "AppVStreamingUXMainOff" fullword
        $s2 = "Process exiting. Restart if allowed." wide fullword
        $s3 = "[ errors in module '" wide fullword
        $s4 = "[Error] Method '' not found in module '" wide fullword
        $s5 = "href=[\"'](.*?/raw/.*?/" wide
        $s6 = "FREE|" wide fullword
        $s7 = "USED|" wide fullword
        $s8 = "GET FAILED:" wide fullword
        $s9 = "PATCH FAILED: " wide fullword
        $s10 = "FILE NOT FOUND IN GIST" wide fullword
        $s11 = "CONTENT FIELD NOT FOUND" wide fullword
        
        $m1 = "StegoLsb" fullword
        $m2 = "CachedModule" fullword
        $m3 = "SystemEvents_SessionEnding" fullword
        $m4 = "ExecuteCoreLogic" fullword
        $m5 = "BuildInputParams" fullword
        $m6 = "SendAsFileFromMemory" fullword
        $m7 = "SendReplyInParts" fullword
        $m8 = "ExecuteLib" fullword
        $m9 = "ExecuteDirectModule" fullword
        $m10 = "ExecuteModule" fullword
        $m11 = "DownloadModuleCode" fullword
        $m12 = "CompileDirectModuleCode" fullword
        $m13 = "CompileModuleCode" fullword
        $m14 = "GistRawLink" fullword
        $m15 = "GetRemoteConfig" fullword
        $m16 = "GetGistJson" fullword
        $m17 = "UpdateGist" fullword

    condition:
        filesize < 100KB and
        uint16be(0) == 0x4D5A and
        (6 of ($s*) or (all of ($m*)))
}
