.code

public DirectSyscallInvoke

DirectSyscallInvoke proc
    mov eax, ecx            
    mov rcx, rdx            
    mov rdx, r8             
    mov r8, r9              
    mov r9, [rsp + 40]
    mov r10, rcx            
    syscall  
    ret                     
DirectSyscallInvoke endp

end