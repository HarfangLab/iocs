rule nhas_reverse_shell_unpacked_large
{
    meta:
        description = "Matches unpacked NHAS reverse_ssh file samples"
        references = "TRR250201"
        hash = "18556a794f5d47f93d375e257fa94b9fb1088f3021cf79cc955eb4c1813a95da"
        date = "2024-09-24"
        author = "HarfangLab"
        context = "file"
    strings:
        $s1 = "/NHAS/reverse_ssh/cmd/client" ascii
        $s2 = "/handlers.runCommandWithPty" ascii
        $s3 = "/connection.RegisterChannelCallbacks" ascii
        $s4 = "/internal.RemoteForwardRequest" ascii
        $s5 = "github.com/pkg/sftp" ascii
        $s6 = "github.com/creack/pty" ascii
        $s7 = "main.Fork" ascii fullword
    condition:
        filesize > 2MB and filesize < 30MB
        and ((uint32be(0) == 0x7F454C46) or (uint16be(0)==0x4D5A))
        and (5 of them)
}

rule nhas_reverse_shell_pe_inmem_large
{
    meta:
        description = "Matches packed NHAS reverse_ssh PE samples in-memory during execution"
        references = "TRR250201"
        hash = "7798b45ffc488356f7253805dc9c8d2210552bee39db9082f772185430360574"
        date = "2024-09-24"
        author = "HarfangLab"
        context = "memory"
    strings:
        $s1 = "\\rprichard\\proj\\winpty\\src\\agent\\" ascii
        $s2 = "\\Users\\mail\\source\\winpty\\src\\" ascii
        $s3 = "Successfully connnected" ascii
        $s4 = "*main.decFunc" ascii fullword
        $s6 = "keepalive-rssh@golang.org" ascii fullword
        $s7 = ".(*sshFxpSetstatPacket)." ascii
    condition:
        (all of them)
}

rule nhas_reverse_shell_elf_inmem_large
{
    meta:
        description = "Matches packed NHAS reverse_ssh ELF samples in-memory during execution"
        references = "TRR250201"
        hash = "9f97997581f513166aae47b3664ca23c4f4ea90c24916874ff82891e2cd6e01e"
        date = "2024-09-24"
        author = "HarfangLab"
        context = "memory"
    strings:
        $s1 = "/NHAS/reverse_ssh/cmd/client" ascii
        $s2 = "/handlers.runCommandWithPty" ascii
        $s3 = "/connection.RegisterChannelCallbacks" ascii
        $s4 = "/internal.RemoteForwardRequest" ascii
        $s7 = "main.Fork" ascii fullword
    condition:
        (all of them)
}
