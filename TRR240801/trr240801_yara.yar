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