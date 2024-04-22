rule Custom_AteraAgent_Operator {
    meta:
        description = "Detect Atera Agent configured to certain email addresses, or email domains"
        references = "TRR240402"
        date = "2024-04-17"
        author = "HarfangLab"
        context = "file"
    strings:
        $email = "email@domain.tld" // Change email address
        $s1 = "PREVIOUSFOUNDWIX_UPGRADE_DETECTED"
        $s2 = "INTEGRATORLOGIN"
        $sc1 = { 0A 28 49 99 78 E5 89 8D F4 0A 23 8E B8 A5 52 E8 } // Atera Network certificate 2024-02-15 - 2025-03-18
        $sc2 = { 06 7F 60 47 95 66 24 A7 15 99 61 74 3D 81 94 93 } // Atera Network certificate 2022-02-17 - 2024-03-16
    condition: 
        filesize > 1MB and filesize < 4MB
        and (uint16be(0) == 0xD0CF)
        and @s1 < @email 
        and @email < @s2[3]
        and any of ($sc*)
}
