global _start

%assign GETDENTS 217
%assign STAT 4
%assign OPEN 2
%assign MMAP 9
%assign MUNMAP 11
%assign CHDIR 80
%assign ACCESS 21

%assign SIZE 1024 * 32 + 128 + 100 		; sizeof (getdents64 + stat + temporary)'s buf				

%define arg(n) rbp + 8 + (n * 8)		; macro to get argument
%define local(n) rbp - (n * 8)			; macro to get local variable

%macro CALLFN 2-*						; macro to call fn. Args = (fn's ptr, path to dir)
	push rdi
	push rsi
	push rbx
	push r8
	push r12
	push %2
	%if %0 == 3							; compiling condition == if put 3 args (2 from these args of fn)
		push %3							; also push 2nd arg
	%endif
	call %1
	%if %0 == 3							; if args == 3
		add rsp, 16						; skip 2 args
	%elif %0 == 2						; else if args = 2
		add rsp, 8						; skip only 1 arg
	%endif
	pop r12
	pop r8
	pop rbx
	pop rsi
	pop rdi
%endmacro

%macro WRITE 3							
	mov rax, 1									
	mov rdi, %1
	mov rsi, %2
	mov rdx, %3
	syscall
%endmacro

%macro RETURN 1
	mov rax, 60
	mov rdi, %1
	syscall
%endmacro

section .rodata
chdem db "Cannot open the dir : ", 0
chdeml_ equ $ - chdem
inpem db "Incorrect input. Try ./shcrypt <key> <dirname>", 10, 0
inpel_ equ $ - inpem
keyem db "Incorrect key : use only '--e' (to encrypt) or '--d' (to decrypt)", 10, 0
keyel_ equ $ - keyem
endls db 0xA
prev_dir db 0x2E, 0x2E, 0x00
sucs db "[+] ", 0
slen_ equ $ - sucs
encrm db "Encrypted - ", 0
enclen_ equ $ - encrm
decrm db "Decrypted - ", 0
errm db "[-] Cannot open - ", 0
errmln_ equ $ - errm

section .data
tbuf times 100 db 0								; target-buf (path to dir)
isencr db 0										; is encrypt? (bool value --> 1 = encrypt, 2 = decrypt)
issucs db 0										; is success? (yes if byte [issucs > 0])

section .text
_start:		cmp qword [rsp], 3					; if command line's args count != 3 => incorrect input
			jne inperr							; goto err

			mov rsi, qword [rsp + 16]			; rsi = pointer to flag-symbol
			cmp dword [rsi], 0x00652D2D			; if key == '--e' => set isencrt to 1
			je setflg
			cmp dword [rsi], 0x00642D2D			; elif key == '--d' do nothing (decrypt)
			jne keyerr							; else undefined key

ag:			mov rsi, qword [rsp + 24]			; source = dirname
			mov rdi, tbuf						; dest = tbuf

mvsb:		cmp byte [rsi], 0					; if dirname ended
			je nxt								; next instructiond
			movsb								; byte from source to dest
			jmp short mvsb						; next iter

nxt:		mov rax, ACCESS						; sys_access
			mov rdi, tbuf						; rdi = object name (start dir)
			xor rsi, rsi						; flag = F_OK
			syscall
			test rax, rax						; if rax < 0 => dir is not exist
			js acs_e

			CALLFN mfn, tbuf			
			pop rax								; just pop rax is programm finished successfully (optional)
			RETURN 0						

setflg:		inc byte [isencr]
			jmp short ag

mfn:		push rbp							; base of stack-frame
			mov rbp, rsp						; save address of base
			xor r12, r12
			sub rsp, 56							; free 7 * 8 bytes to 7 local vars
												; (1) -> dynamic pointer to buffers
												; (2) -> opened dir's fd
												; (3) -> sizeof linux-dirent (reclen)
												; (4) -> pointer to file-name
												; (5) -> pointer to stat-buf
												; (6) -> static pointer to buffers
												; (7) -> readed bytes from getdents

			mov rax, MMAP						; sys_mmap (like malloc in this context)
			xor rdi, rdi						; address = NULL
			mov rsi, SIZE 						; size for : linux-dirent, stat
			mov rdx, 0x3 						; PROT_READ | PROT_WRITE
			mov r10, 0x2 | 0x20					; MAP_PRIVATE |  MAP_ANONYMUS
			mov r8, -1							; without fd
			xor r9, r9							; offset = NULL
			syscall
			test rax, rax
			js .mfnend

			mov qword [ local(1) ], rax			; save ptr to linux-dirent structs as the 1st local-var
			mov qword [ local(6) ], rax			; save static ptr to structs 
			add rax, 1024 * 32
			mov qword [ local(4) ], rax			; save ptr to stat-buf
			add rax, 128
			mov qword [ local(5) ], rax			; save ptr to filename-buf

			mov rax, OPEN						; sys_open
			mov rdi, [ arg(1) ]					; path
			mov rsi, 0x0 | 0x4					; O_READ | O_EXECUTE
			mov rdx, 0o777						; -rwxrwxrwx
			syscall								
			test rax, rax						; if rax < 0
			js .mfnend							; err (skip this dir)
			mov qword [ local(2) ], rax			; save fd to dir as the 2nd local-var

			mov rax, CHDIR						; sys change_dir
			mov rdi, qword [ arg(1) ]			; entered path
			syscall
			test rax, rax
			js .mfnend							

.checkdir:	mov rax, GETDENTS					; sys_getdents64
			mov rdi, qword [ local(2) ]			; put fd
			mov rsi, qword [ local(6) ] 		; buf for linux_dirent structs
			mov rdx, SIZE - 128	- 100			; rdx = sizeof buf (getdents + stat + tmp) - stat - tmp
			syscall		
			mov rbx, qword [ local(6) ]			; return static address to rbx (1st byte ptr)
			mov qword [ local(1) ], rbx			; return dynamic address to local(1)
			test rax, rax						; if rax == 0 => all linux-dirents were watched
			jz .mfnend
			js .mfnend							; if rax < 0 => cannot get data => skip dir
			mov qword [ local(7) ], rax			; set parsed bytes

.rtrn:		cmp qword [ local(7) ], 0			; if byte to read == 0 -> all structures were parsed
			jle .checkdir						; go on 

			add rsi, 16							; offset to reclen
			movzx rsi, word [rsi]				; get reclen
			mov qword [ local(3) ], rsi 		; 3rd local arg = reclen

			mov rsi, qword [ local(1) ]			
			add rsi, 19							; source = d_name[]
			mov rdi, qword [ local(4) ]			; dest = temporary-buf

			cmp word [rsi], 0x002E				; if cheking dir is "." (especcialy current dir)
			je .newit							; continue
			cmp word [rsi], 0x2E2E				; if checking dir is ".." (previous dir)
			je .newit							; also continue

			xor r12, r12						; r12 = strlen of filename

.movlp:		cmp byte [rsi], 0					; if current symbol == '\0' (while current symbol != 0)
			je .nxt								; string already parsed
			movsb								; sourse -> dest (1 byte)
			inc r12								; ++strlen
			jmp short .movlp					; next iteration

.nxt:		mov rsi, qword [ local(1) ]				
			add rsi, 18							; get address of 'd_type' field
			cmp byte [rsi], 0x4					; if type of object is dir
			je .nxtcall							; recurse call
			CALLFN encrpt, qword [ local(4) ], qword [ local(5) ]; else it's file => call encrypt-fn with arg = filename's buf

.newit:		mov rsi, qword [ local(1) ]			; put current address of getdents-buf's current linux-dirent
			add rsi, qword [ local(3) ]			; rsi += reclen
			mov qword [ local(1) ], rsi			; update address of current linux-dirent
			xor rax, rax						; al = 0
			mov rcx, r12						; rcx = strlen
			xor r12, r12						; r12 = 0
			mov rdi, qword [ local(4) ]			; rdi = filename
			rep stosb							; zero filling
			mov rbx, qword [ local(7) ]			; update parsed bytes 
			sub rbx, qword [ local(3) ]			; PARSED BYTES - PARSET BYTES ON CURR ITER
			mov qword [ local(7) ], rbx			; return changes
			jmp .rtrn							; next check

.mfnend:	mov rax, MUNMAP						; sys_munmap
			mov rdi, qword [ local(6) ]			; pointer from which mem will be free
			mov rsi, SIZE						; sizeof bytes for free
			syscall

			mov rax, 3							; sys_close						
			mov rdi, qword [ local(2) ]			; dir fd
			syscall

			mov rsp, rbp						; basic ret-stack-frame procedure
			pop rbp
			ret

.nxtcall:	CALLFN mfn, qword [ local(4) ]		; call encryption fn(*filename, *statbuf)
			mov rax, CHDIR						; go back to the previous dir
			mov rdi, prev_dir					; rdi = "..\0"
			syscall
			jmp short .newit					; next iteration

; --------------- encrypt file --------------
encrpt:		push rbp						; base of stack-frame
			mov rbp, rsp					; rbp = address of base of stack-frame
			
			sub rsp, 24						; reserve space to 3 local vars
											; (1) -> sizeof file
											; (2) -> fd
											; (3) -> pointer to mapped file

			mov rax, STAT					; sys_stat
			mov rdi, qword [ arg(2) ]		; filename
			mov rsi, qword [ arg(1) ]		; statbuf
			syscall	
			test rax, rax					; if something went wront -> return 
			js .nxt
			add rsi, 48						; offset to 't_size' field
			mov rsi, qword [rsi]
			mov qword [ local(1) ], rsi		; if ok -> 1st sizeof file

			mov rax, OPEN					; sys_open
			mov rdi, qword [ arg(2) ]		; path
			mov rsi, 0x2 					; O_READ | 0_WRITE
			mov rdx, 0x666					; -rw-rw-rw
			syscall	
			test rax, rax
			js .nxt
			inc byte [issucs]				; ++success 
			mov qword [ local(2) ], rax		; 2nd local = fd

			mov rax, MMAP					; sys_mmap
			xor rdi, rdi					; address = NULL
			mov rsi, qword [ local(1) ]		; size = sizeof file
			mov rdx, 0x3					; PROT_READ | PROT_WRITE
			mov r10, 0x1					; MAP_SHARED
			mov r8, qword [ local (2) ]		; fd
			xor r9, r9						; offset = NULL
			syscall
			test rax, rax
			js .nxt
			inc byte [issucs]				; ++success 
			mov qword [ local(3) ], rax		; 3rd arg = pointer to mapped file

			mov rcx, qword [ local(1) ]		; rcx = sizeof file
			jrcxz .nxt						; if rcx == 0 -> skip

			cmp byte [isencr], 0			; if isencr == 0
			je .decrlp						; let's decrypt

.encrlp:	add byte [rax], 42				; Caesar encryption (add 42 to each byte)
			not byte [rax]					; bit-inversion
			sub byte [rax], 22				; -22
			xor byte [rax], 0b00110101		; and xor bit-mask
			inc rax							; next byte
			loop .encrlp					; --rcx && jmp .encrlp
			jmp .nxt						; goto .nxt right now (we don't need to go to decrypt loop)

.decrlp:	xor byte [rax], 0b00110101		; remove xor
			add byte [rax], 22				; +22
			not byte [rax]					; again not	
			sub byte [rax], 42				; decription (-42)
			inc rax							; next byte
			loop .decrlp					; --rcx && jmp .decrlp

.nxt:		cmp byte [issucs], 0			; if issucs == 0 => open error => exception
			jz .fail						; fail message
.rt:		WRITE 1, sucs, slen_			; else put success symbol [+]
			cmp byte [isencr], 0			; if not encrypted
			je .wrdec						; write decrypt message
			WRITE 1, encrm, enclen_			; else write encrypt message
			jmp .cnt						; and continue 
			
.fail:		WRITE 1, errm, errmln_			; write fail message
			jmp .cnt

.wrdec:		WRITE 1, decrm, enclen_			; write decrypt message

.cnt:		WRITE 1, qword [ arg(2) ], r12	; write filename
			WRITE 1, endls, 1				; put '\n'

			cmp byte [issucs], 0			; if issucs == 0 => open error => just leave
			jmp .rtrn

			mov rax, MUNMAP					; sys_munmap
			mov rdi, qword [ local(3) ]		; rdi = pointer to mapped file
			mov rsi, qword [ local(1) ]		; rsi = sizeof file
			syscall

			mov rax, 3						; sys_close
			mov rdi, qword [ local(2) ]		; get fd
			syscall

.rtrn:		mov byte [issucs], 0			; set flag to zero			

			mov rsp, rbp					; return stack-ptr to base
			pop rbp							; rsp += 8 && rbp got previous base
			ret								; mov rip, qword [rsp] && rsp += 8

acs_e:		WRITE 1, chdem, chdeml_
			WRITE 1, tbuf, 100
			WRITE 1, endls, 1				
			RETURN 3

inperr:		WRITE 1, inpem, inpel_
			RETURN 1

keyerr:		WRITE 1, keyem, keyel_
			RETURN 2
€
