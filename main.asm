include main.inc
.code
start:
     call main
     ;----------
     push eax
     call ExitProcess
;==============================
main proc
        
    fn initializer
    ;-------------------
    or eax,eax
    je @@Ret
    ;-------------------
    ;mov eax,input("Enter something",62," ")
    ;-------------------
    fn thread_hijack_injector,&szTargetW,&injectDll
    ;-------------------
    or eax,eax
    jne @F
    ;---------------
    printf("\nFailed to inject DLL\n")
    ;---------------
    jmp @@Ret
@@:
    ;---------------
    printf("\nDll injected!\n")
    ;---------------
@@Ret:
    inkey
    xor eax,eax
	ret
main endp     
end start