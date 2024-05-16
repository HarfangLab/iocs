rule MuddyWater_AteraAgent_Operators {
    meta:
        description = "Detect Atera Agent abused by MuddyWater"
        references = "TRR240402"
        hash = "9b49d6640f5f0f1d68f649252a96052f1d2e0822feadd7ebe3ab6a3cadd75985"
        date = "2024-04-17"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "COMPANYID001Q3000009snPyIAIACCOUNTID"
        $s2 = "COMPANYID001Q3000006FpmoIACACCOUNTID" 
        $s3 = "COMPANYID001Q3000008IyacIACACCOUNTID"
        $s4 = "COMPANYID001Q3000009QoSEIA0ACCOUNTID"
        $s5 = "COMPANYID001Q30000023c7iIAAACCOUNTID"
        $s6 = "COMPANYID001Q3000008qXbDIAUACCOUNTID"
        $s7 = "COMPANYID001Q3000008cfLjIAIACCOUNTID"
        $s8 = "COMPANYID001Q3000007hJubIAEACCOUNTID"
        $s9 = "COMPANYID001Q3000008ryO3IAIACCOUNTID"
        $s10 = "COMPANYID001Q300000A5nnAIARACCOUNTID"
        $s11 = "COMPANYID001Q3000008JfioIACACCOUNTID"
        $s12 = "COMPANYID001Q300000BeUp3IAFACCOUNTID" 
        $s13 = "COMPANYID001Q3000005gMamIAEACCOUNTID"
        $s15 = "mrrobertcornish@gmail.comINTEGRATORLOGINCOMPANYID"

        $cert1 = { 0A 28 49 99 78 E5 89 8D F4 0A 23 8E B8 A5 52 E8 } // Atera Network certificate 2024-02-15 - 2025-03-18
        $cert2 = { 06 7F 60 47 95 66 24 A7 15 99 61 74 3D 81 94 93 } // Atera Network certificate 2022-02-17 - 2024-03-16

    condition: 
        filesize > 1MB and filesize < 4MB
        and (uint16be(0) == 0xD0CF)
        and any of ($s*)
        and any of ($cert*)
}