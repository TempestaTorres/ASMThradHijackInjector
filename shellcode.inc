;======================================================
;Disassembly: https://defuse.ca/online-x86-assembler.htm#disassembly
;======================================================

.code
shell_start proc

    ;Save registers

	pushad
	pushfd
	call @@start               ;Get the delta offset
    ;-----------
@@start:
    pop ecx
    sub ecx,7
	lea eax,dword ptr[ecx+21] ;21 byte is a Code length
	push eax
	;-----------
	call dword ptr[ecx-4]     ;LoadLibraryA address is stored before the shellcode

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