MAX_API_STRING_LENGTH     = 150

TIB_INFO struct

    seh	         DWORD  ?
    topstack	 DWORD  ?
    bottomstack	 DWORD  ?
    tibOffset	 DWORD  ?
    
TIB_INFO ends

TEB_INFO struct

    ProcessId	                 DWORD ?
    threadId	                 DWORD ?  
    ThreadLocalStoragePointer    DWORD ? 
    Peb	                         DWORD ? 
    LastErrorValue	             DWORD ? 
    ExceptionCode	             DWORD ?
    TlsSlots                     DWORD ?

TEB_INFO ends

ANTIDEBUG_INFO struct

    BeingDebugged     DWORD ?
    NtGlobalFlag      DWORD ?
    WoW64NtGlobalFlag DWORD ?
    HeapFlags         DWORD ?
    ForceFlags        DWORD ?

ANTIDEBUG_INFO ends

get_tibinfo32                            proto :DWORD
get_tebinfo32                            proto :DWORD
get_debuginfo32                          proto :DWORD

get_pebBaseAddress32                     proto
get_pebLdrData32                         proto
get_InInitializationOrderModuleListFlink proto 
get_ImageBase32                          proto

get_PEBFunction32                        proto :DWORD,:DWORD
get_ProcAddr32                           proto :DWORD,:DWORD

.data
ntdllName         dw 'n','t','d','l','l','.','d','l','l',0
kernelbaseName    dw 'K','E','R','N','E','L','B','A','S','E','.','d','l','l',0
kernelName        dw 'K','E','R','N','E','L','3','2','.','D','L','L',0

;--------------------------------------
szLoadLibrary     db "LoadLibraryA",0
szGetProcAddress  db "GetProcAddress",0
szUser32          db "user32",0
;-------------------------------------
@LoadLibraryA     dd 0
@GetProcAddress   dd 0

.code
;==============================================================
get_pebBaseAddress32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
    
	ret
get_pebBaseAddress32 endp
;==============================================================
get_pebLdrData32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
    ;-------------------------
    mov eax,dword ptr[eax+0Ch]   ;EAX contains the address of the PEB_LDR_DATA structure.
	ret
get_pebLdrData32 endp
;==============================================================
get_InInitializationOrderModuleListFlink proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
    ;-------------------------
    mov eax,dword ptr[eax+0Ch]
    mov eax,dword ptr[eax+1Ch] ;EAX is the address of PEB-> Ldr.InInitializationOrderModuleList.Flink
    
	ret
get_InInitializationOrderModuleListFlink endp
;==============================================================
get_ImageBase32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    ;-----------------------
    mov eax,dword ptr[eax+8]
	ret
get_ImageBase32 endp
;==============================================================
get_tibinfo32 proc uses ebx esi edi ti:DWORD

    mov esi,ti
    ;----------------
    assume fs:nothing
    mov eax,dword ptr fs:[0]
    mov dword ptr[esi],eax
    ;----------------
    mov eax,dword ptr fs:[4]
    mov edx,dword ptr fs:[8]
    ;----------------
    mov dword ptr[esi+4],eax
    mov dword ptr[esi+8],edx
    ;----------------
    mov eax,dword ptr fs:[18h]
    mov dword ptr[esi+0Ch],eax
    ;----------------
    mov eax,esi

	ret
get_tibinfo32 endp
;==============================================================
get_tebinfo32 proc uses ebx esi edi ti:DWORD

    mov esi,ti
    ;----------------
    assume fs:nothing
    mov eax,dword ptr fs:[20h]
    mov edx,dword ptr fs:[24h]
    mov dword ptr[esi+TEB_INFO.ProcessId],eax
    mov dword ptr[esi+TEB_INFO.threadId],edx
    ;----------------
    mov eax,dword ptr fs:[2Ch]
    mov dword ptr[esi+TEB_INFO.ThreadLocalStoragePointer],eax
    ;----------------
    mov eax,dword ptr fs:[30h]
    mov dword ptr[esi+TEB_INFO.Peb],eax
    ;----------------
    mov eax,dword ptr fs:[34h]
    mov dword ptr[esi+TEB_INFO.LastErrorValue],eax
    ;----------------
    mov eax,dword ptr fs:[5Ch]
    mov dword ptr[esi+TEB_INFO.ExceptionCode],eax
    ;----------------
    mov eax,dword ptr fs:[0C0h]
    mov dword ptr[esi+TEB_INFO.TlsSlots],eax
    ;----------------
    mov eax,esi

	ret
get_tebinfo32 endp
;==============================================================
get_debuginfo32 proc uses ebx esi edi ai:DWORD

    mov esi,ai
    ;----------------
    assume fs:nothing
    ;----------------
    mov ebx,dword ptr fs:[30h]
    movzx eax,byte ptr[ebx+2]
    mov dword ptr[esi],eax
    ;----------------
    mov eax,dword ptr[ebx+68h]
    mov dword ptr[esi+4],eax
    ;----------------
    mov eax,dword ptr fs:[18h]
    sub eax, 2000h
    mov eax,dword ptr[eax+60h]
    movzx eax,byte ptr[eax+0BCh]
    mov dword ptr[esi+8],eax
    ;-----------------
    mov eax, dword ptr[ebx+18h]
    mov eax, dword ptr[eax+40h]
    mov dword ptr[esi+0Ch],eax
    ;----------------
    mov eax, dword ptr[ebx+18h]
    mov eax, dword ptr[eax+44h]
    mov dword ptr[esi+10h],eax
    ;----------------
    mov eax,esi
	ret
get_debuginfo32 endp
;==============================================================
;Input DllName in Unicode String!
;==============================================================
get_PEBFunction32 proc uses ebx esi edi dllName:DWORD,lpFunctionName:DWORD
    LOCAL lens:DWORD
    
    ;---------------------------------------
    ;get the string length of the target dll
    ;---------------------------------------
    
    push dllName
    pop edi
    ;-------------
	mov ecx, 64h
	xor eax,eax
	repne scasw
	mov ecx,edi
	sub ecx, dllName
	shr ecx,1
	mov lens,ecx
    ;------------------
    call get_InInitializationOrderModuleListFlink
    ;------------------
    mov ebx,eax
@@:
    mov eax,dword ptr[ebx+20h] ; EAX contains the address of the module’s name in the form of its Unicode string.
    ;-------------------
    or eax,eax
    je @@Ret
    ;-------------------
    mov ecx,lens
    mov edi,eax
    mov esi,dllName
    ;-------------------
    repe cmpsw
    ;-------------------
    jne @@Next
    
    ;-------------------
    ;GET DLL BASE ADDRESS
    ;--------------------
    
    mov eax,dword ptr[ebx+8]
    ;--------------------
    push lpFunctionName
    push eax
    ;--------------------
    call get_ProcAddr32
    ;--------------------
    jmp @@Ret
@@Next:
    ;-------------------
    mov ebx,dword ptr[ebx]
    or ebx,ebx
    jne @B
    
@@Ret:
	ret
get_PEBFunction32 endp
;==============================================================
get_ProcAddr32 proc uses ebx esi edi base:DWORD,procName:DWORD
   
    ;---------------------------------------
    ;get the string length of the target Api
    ;---------------------------------------
    
    push procName
    pop edi
    ;-------------
	mov ecx, MAX_API_STRING_LENGTH
	xor al,al
	repne scasb
	mov ecx,edi
	sub ecx, procName
	;-------------
	push base
	pop esi
	add esi,dword ptr[esi+3Ch]
	
	;-----------------------
	; trace the export table
	;-----------------------
	
	mov edx,dword ptr[esi+78h]    ;Export table RVA
	
	;-----------------------
	;Get Export Table Address
	;-----------------------
	
	add edx,base                  ;edx -> ExportTable
	mov ebx,dword ptr[edx+20h]    ;ebx -> RVA of Array Functions Names
	add ebx,base                  ;ebx -> Array of Names
	
	;------------------------
	;Loop array
	;------------------------
	
	xor eax,eax
@@For:
    mov edi,dword ptr[ebx+eax*4]  ;RVA of name string
    add edi,base
    ;------------------------
    push procName
    pop esi
    ;------------------------
    push ecx                      ;save string length
    ;------------------------
    repe cmpsb
    ;------------------------
    pop ecx
    je @@Done
    ;------------------------
@@Next:
    inc eax
    cmp eax,dword ptr[edx+18h]    ;+18  (24) DWORD 	NumberOfNames
    jl @@For
@@Done:
    cmp eax,dword ptr[edx+18h]    ; did we found ?
    jb @F
    ;------------------------
    xor eax,eax
    jmp @@Ret
@@:
    ;------------------------------
    ;find the corresponding Ordinal 
    ;eax -> index to the array
    ;------------------------------
    
    mov esi,dword ptr[edx+24h]    ;+24  (36) DWORD 	*AddressOfNameOrdinals
    add esi,base                  ;esi -> Address to Array
    ;------------------------
    movzx ecx,word ptr[esi+eax*2] ; ordinal    
    ;------------------------
    mov esi,dword ptr[edx+1Ch]
    add esi,base                  ;*AddressOfFunctions
    ;-------------------------
    mov eax,dword ptr[esi+ecx*4]
    add eax,base

@@Ret:
	ret
get_ProcAddr32 endp
;==============================================================