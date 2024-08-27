rule apt31_rawdoor_dropper 
{ 
    meta: 
        description = "Matches the RawDoor dropper" 
        references = "TRR240401" 
        hash = "c3056e39f894ff73bba528faac04a1fc86deeec57641ad882000d7d40e5874be" 
        date = "2024-04-12" 
        author = "HarfangLab" 
        context = "file" 
    strings: 
        $service_target = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii 
        $service_dispname = "Microsoft .NET Framework NGEN" ascii 
        $drop_name = "~DF313.msi" ascii 
        $msg1 = "RegOpenKeyEx %s  error:%d\x0D\x0A" ascii 
        $msg2 = "RegDeleteValue Wow64 . %d\x0D\x0A" ascii 
        $msg3 = "CreateService %s success! but Start Faile.. %d\x0D\x0A" ascii 
        $msg4 = "OutResFile to %s%s False!" ascii 
        $msg5 = "Can't GetNetSvcs Buffer!" ascii 
    condition: 
        uint16(0) == 0x5A4D and filesize > 350KB and filesize < 600KB and 
        (($service_target and $service_dispname and $drop_name) or 3 of ($msg*)) 
}

rule apt31_rawdoor_payload 
{ 
    meta: 
        description = "Matches the RawDoor payload" 
        references = "TRR240401" 
        hash = "fade96ec359474962f2167744ca8c55ab4e6d0700faa142b3d95ec3f4765023b" 
        date = "2024-04-12" 
        author = "HarfangLab" 
        context = "file" 
    strings: 
        $name = "\x0D\x0A=================RawDoor %g================\x0D\x0A" ascii 
        $key = /SOFTWARE\\Clients\\Netra(u|w)/ ascii 
        $cmd1 = "Shell <powershell.exe path>" ascii 
        $cmd2 = "Selfcmd <self cmd string>" ascii 
        $cmd3 = "Wsrun <process name>" ascii 
        $cmd4 = "ping 127.0.0.1 > nul\x0D\x0A" 
        $cmd5 = "/c netsh advfirewall firewall add rule name=" ascii 
        $msg1 = "Allocate pSd memory to failed!" ascii 
        $msg2 = "Allocate SID or ACL to failed!" ascii 
        $msg3 = "OpenSCManager error:%d" ascii 
        $msg4 = "%u:TCP:*:Enabled:%u" ascii 
    condition: 
        uint16(0) == 0x5A4D and filesize < 200KB and 
        (($name and $key) or (3 of ($cmd*) and 3 of ($msg*))) 
}