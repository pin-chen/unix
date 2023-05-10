	sub	rsp, 8
	lea	edx, -1[rsi]
	mov	esi, 0
	call	quicksort
	add	rsp, 8
	ret
quicksort:
	push	r12
	push	rbp
	push	rbx
	mov	rbp, rdi
	mov	r9d, esi
	mov	r10d, edx
	sub	r10d, esi
	cmp	r10d, 72
	jle	.L17
	mov	r12d, edx
	lea	edx, [rdx+rsi]
	mov	eax, edx
	shr	eax, 31
	add	eax, edx
	sar	eax
	cdqe
	mov	rax, QWORD PTR [rdi+rax*8]
	mov	edx, r12d
	mov	ebx, esi
	jmp	.L13
.L17:
	movsx	r9, esi
	lea	rsi, [rdi+r9*8]
	mov	r8d, 1
	jmp	.L3
.L6:
	mov	QWORD PTR 8[rsi+rcx*8], rdx
	sub	eax, 1
.L4:
	test	eax, eax
	js	.L5
	movsx	rcx, eax
	mov	rdx, QWORD PTR [rsi+rcx*8]
	cmp	rdx, rdi
	jg	.L6
.L5:
	cdqe
	mov	QWORD PTR 8[rsi+rax*8], rdi
	add	r8d, 1
.L3:
	cmp	r10d, r8d
	jl	.L1
	movsx	rax, r8d
	mov	rdi, QWORD PTR [rsi+rax*8]
	lea	eax, -1[r8]
	jmp	.L4
.L10:
	add	ebx, 1
.L14:
	movsx	rcx, ebx
	lea	rdi, 0[rbp+rcx*8]
	mov	rsi, QWORD PTR [rdi]
	cmp	rsi, rax
	jl	.L10
	jmp	.L11
.L12:
	sub	edx, 1
.L11:
	movsx	rcx, edx
	lea	rcx, 0[rbp+rcx*8]
	mov	r8, QWORD PTR [rcx]
	cmp	r8, rax
	jg	.L12
	cmp	ebx, edx
	jle	.L18
.L13:
	cmp	ebx, edx
	jle	.L14
	cmp	edx, r9d
	jg	.L19
.L15:
	cmp	ebx, r12d
	jl	.L20
.L1:
	pop	rbx
	pop	rbp
	pop	r12
	ret
.L18:
	mov	QWORD PTR [rdi], r8
	mov	QWORD PTR [rcx], rsi
	add	ebx, 1
	sub	edx, 1
	jmp	.L13
.L19:
	mov	esi, r9d
	mov	rdi, rbp
	call	quicksort
	jmp	.L15
.L20:
	mov	edx, r12d
	mov	esi, ebx
	mov	rdi, rbp
	call	quicksort
	jmp	.L1