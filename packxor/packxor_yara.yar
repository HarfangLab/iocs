rule PackXOR
{
    meta:
        description = "Detection rule for PackXOR"
        references = "https://harfanglab.io/insidethelab/unpacking-packxor/"
        hash = "0506372e2c2b6646c539ac5a08265dd66d0da58a25545e444c25b9a02f8d9a44"
        date = "2024-08-05"
        author = "Harfanglab"
        context = "file"
    strings:
        $s_packer_xor = {
            4? 63 [3]                       // movsxd  rax, dword [rsp+0x50 {var_78}]
            4? 8b [2-6]                     // mov     rcx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rcx, qword [rcx+0x8]
            4? 0? [2]                       // add     rax, qword [rcx+0x50]
            4? 8d [5]                       // lea     rcx, [rel data_140003020]
            0f (b6|b7) [1-5]                // movzx   eax, byte [rcx+rax]
            0f (b6|b7) [1-5]                // movzx   ecx, byte [rel data_14002399c]
            4? 8b [2-6]                     // mov     rdx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rdx, qword [rdx+0x8]
            4? 0? [2]                       // add     rcx, qword [rdx+0x68]
            0f (b6|b7) [1-5]                // movzx   ecx, cl
            33 ??                           // xor     eax, ecx
            4? 63 [3]                       // movsxd  rcx, dword [rsp+0x50 {var_78}]
            4? 8b [2-6]                     // mov     rdx, qword [rsp+0xd0 {arg_8}]
            4? 8b [2-6]                     // mov     rdx, qword [rdx+0x8]
            4? 0? [2]                       // add     rcx, qword [rdx+0x48]
            4? 8d [5]                       // lea     rdx, [rel data_140003020]
            88 04 0a                        // mov     byte [rdx+rcx], al
            0f (b6|b7)                      // movzx   eax, byte [rel data_14000301e]
        }
        $s_packer_decrypt_conf = {
            8b [1-3]            // mov     eax, dword [rsp+0x4 {i}]
            ff ??               // inc     eax
            89 [1-3]            // mov     dword [rsp+0x4 {i}], eax
            0f b6 [1-3]         // movzx   eax, byte [rsp {var_128}]
            39 [1-3]            // cmp     dword [rsp+0x4 {i}], eax
            73 ??               // jae     0x140001d59
            8b [1-3]            // mov     eax, dword [rsp+0x4 {i}]
            83 ?? 05            // add     eax, 0x5
            8b ??               // mov     eax, eax
            4? 8b [2-6]         // mov     rcx, qword [rsp+0x130 {arg_8}]
            0f be [1-3]         // movsx   eax, byte [rcx+rax]
            85 ??               // test    eax, eax
            74 ??               // je      0x140001d40
            0f b6 [1-3]         // movzx   eax, byte [rsp+0x2 {var_126}]
            8b [3]              // mov     ecx, dword [rsp+0x4 {i}]
            83 ?? 05            // add     ecx, 0x5
            8b ??               // mov     ecx, ecx
            4? 8b [4-6]         // mov     rdx, qword [rsp+0x130 {arg_8}]
            0f (be|bf) [1-3]    // movsx   ecx, byte [rdx+rcx]
            33 ??               // xor     eax, ecx
            2b [1-3]            // sub     eax, dword [rsp+0x4 {i}]
            ff ??               // dec     eax
            8b [1-3]            // mov     ecx, dword [rsp+0x4 {i}]
            88 [1-3]            // mov     byte [rsp+rcx+0x20 {var_108}], al
            eb ??               // jmp     0x140001d57
            b8 01 00 00 00      // mov     eax, 0x1
            4? 6b ?? 00         // imul    rax, rax, 0x0
            4? 8b [4-6]         // mov     rcx, qword [rsp+0x130 {arg_8}]
            c6 [1-3] 00         // mov     byte [rcx+rax], 0x0
            eb ??               // jmp     0x140001d59
            eb                  // jmp     0x140001ce7
        }
        $s_packer_find_entry_point = {
            4? 63 [1-4]             // movsxd  rax, dword [rsp {var_38_1}]
            4? 3b [1-4]             // cmp     rax, qword [rsp+0x20 {var_18_1}]
            73 ??                   // jae     0x140001c7f
            48 8b [1-4]             // mov     rax, qword [rsp+0x10 {var_28_1}]
            0f b7 [1-4]             // movzx   eax, word [rax]
            c1 ?? 0c                // sar     eax, 0xc
            83 ?? 0a                // cmp     eax, 0xa
            75 ??                   // jne     0x140001c7d
            4? 8b [1-4]             // mov     rax, qword [rsp+0x8 {var_30}]
            8b [1-4]                // mov     eax, dword [rax]
            4? 03 [1-4]             // add     rax, qword [rsp+0x40 {arg_8}]
            4? 8b [1-4]             // mov     rcx, qword [rsp+0x10 {var_28_1}]
            0f b7 [1-4]             // movzx   ecx, word [rcx]
            81 ?? ff 0f 00 00       // and     ecx, 0xfff
            4? 63 [1-4]             // movsxd  rcx, ecx
            4? 03 [1-4]             // add     rax, rcx
            4? 89 [1-4]             // mov     qword [rsp+0x18 {var_20_1}], rax
            4? 8b [1-4]             // mov     rax, qword [rsp+0x18 {var_20_1}]
            4? 8b [1-4]             // mov     rax, qword [rax]
            4? 03 [1-4]             // add     rax, qword [rsp+0x50 {arg_18}]
            4? 8b [1-4]             // mov     rcx, qword [rsp+0x18 {var_20_1}]
            4? 89 [1-4]             // mov     qword [rcx], rax
            eb 93                   // jmp     0x140001c12
        }
        $s_packer_find_entry_point_rtlcreateuserthtread = {
            4? 8b [1-4]                // mov     rax, qword [rsp+0x70 {var_58_1}]
            8b [1-4]                   // mov     eax, dword [rax+0x28]
            4? 03 [1-4]                // add     rax, qword [rsp+0x68 {var_60_1}]
            4? 89 [2-6]                // mov     qword [rsp+0x88 {var_40_1}], rax
            ff [2-6]                   // call    qword [rsp+0x88 {var_40_1}]
            4? 8d [2-6]                // lea     rax, [rsp+0x9c {var_2c}]
            4? 89 [1-4]                // mov     qword [rsp+0x48 {var_80_1}], rax {var_2c}
            4? 8d [2-6]                // lea     rax, [rsp+0xb8 {var_10}]
            4? 89 [1-4]                // mov     qword [rsp+0x40 {var_88_1}], rax {var_10}
            4? c7 [3-7]                // mov     qword [rsp+0x38 {var_90}], 0x0
            4? 8b [2-6]                // mov     rax, qword [rsp+0x88 {var_40_1}]
            4? 89 [1-4]                // mov     qword [rsp+0x30 {var_98_1}], rax
            4? c7 [3-7]                // mov     qword [rsp+0x28 {var_a0}], 0x0
            4? c7 [3-7 ]               // mov     qword [rsp+0x20 {var_a8}], 0x0
            4? 33 ??                   // xor     r9d, r9d  {0x0}
            4? ?? 01                   // mov     r8b, 0x1
            33 ??                      // xor     edx, edx  {0x0}
            4? c? ?? ff ff ff ff       // mov     rcx, 0xffffffffffffffff
            ff                         // call    qword [rsp+0xa0 {var_28_1}]
        }
        $s_packer_string_encryption = {
            0f B? [1-2]      // movzx   eax, [rsp+128h+size_string]
            39 [1-3]         // cmp     [rsp+128h+var_124], eax
            73 ??            // jnb     short loc_140001CC9
            8B [1-3]         // mov     eax, [rsp+128h+var_124]
            83 ?? 05         // add     eax, 5
            8B ??            // mov     eax, eax
            4? 8B [1-6]      // mov     rcx, [rsp+128h+arg_0]
            0F B? [1-2]      // movsx   eax, byte ptr [rcx+rax]
            85 ??            // test    eax, eax
            74 ??            // jz      short loc_140001CB0
            0f B? [1-3]      // movzx   eax, [rsp+128h+key]
            8B [1-3]         // mov     ecx, [rsp+128h+var_124]
            83 ?? 05         // add     ecx, 5
            8B ??            // mov     ecx, ecx
            4? 8B [1-6]      // mov     rdx, [rsp+128h+arg_0]
            0F B? [1-2]      // movsx   ecx, byte ptr [rdx+rcx]
            33 ??            // xor     eax, ecx
            2B [1-3]         // sub     eax, [rsp+128h+var_124]
            FF ??            // dec     eax
            8B [1-3]         // mov     ecx, [rsp+128h+var_124]
            88 [1-3]         // mov     [rsp+rcx+128h+decrypted_string], al
            EB               // jmp     short loc_140001CC7
        }
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 20MB
        and 2 of ($s_packer*)
}
