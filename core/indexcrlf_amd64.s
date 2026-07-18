//go:build amd64

#include "textflag.h"

DATA crconst<>+0(SB)/8, $0x0D0D0D0D0D0D0D0D
DATA crconst<>+8(SB)/8, $0x0D0D0D0D0D0D0D0D
DATA crconst<>+16(SB)/8, $0x0D0D0D0D0D0D0D0D
DATA crconst<>+24(SB)/8, $0x0D0D0D0D0D0D0D0D
GLOBL crconst<>(SB), RODATA|NOPTR, $32

// func indexCRLF4AVX2(p *byte, n int) int
TEXT ·indexCRLF4AVX2(SB), NOSPLIT, $0-24
	MOVQ p+0(FP), SI
	MOVQ n+8(FP), CX
	MOVL $0x0A0D0A0D, R11
	XORQ AX, AX
	CMPQ CX, $4
	JL   notfound
	CMPQ CX, $32
	JL   tail
	VMOVDQU crconst<>(SB), Y1

loop32:
	MOVQ AX, DX
	ADDQ $32, DX
	CMPQ DX, CX
	JG   tail
	VMOVDQU (SI)(AX*1), Y0
	VPCMPEQB Y1, Y0, Y2
	VPMOVMSKB Y2, BX
	TESTL BX, BX
	JZ    next32

cbits:
	BSFL BX, DI
	MOVQ AX, R8
	ADDQ DI, R8
	MOVQ R8, R9
	ADDQ $4, R9
	CMPQ R9, CX
	JG   clearbit
	CMPL (SI)(R8*1), R11
	JE   found_r8
clearbit:
	MOVL BX, R10
	DECL R10
	ANDL R10, BX
	JNZ  cbits

next32:
	ADDQ $32, AX
	JMP  loop32

tail:
	MOVQ AX, DX
	ADDQ $4, DX
	CMPQ DX, CX
	JG   notfound
	CMPL (SI)(AX*1), R11
	JE   found_ax
	INCQ AX
	JMP  tail

found_ax:
	VZEROUPPER
	MOVQ AX, ret+16(FP)
	RET
found_r8:
	VZEROUPPER
	MOVQ R8, ret+16(FP)
	RET
notfound:
	VZEROUPPER
	MOVQ $-1, ret+16(FP)
	RET

// func indexCRLF2AVX2(p *byte, n int) int
TEXT ·indexCRLF2AVX2(SB), NOSPLIT, $0-24
	MOVQ p+0(FP), SI
	MOVQ n+8(FP), CX
	MOVW $0x0A0D, R11
	XORQ AX, AX
	CMPQ CX, $2
	JL   notfound2
	CMPQ CX, $32
	JL   tail2
	VMOVDQU crconst<>(SB), Y1

loop2:
	MOVQ AX, DX
	ADDQ $32, DX
	CMPQ DX, CX
	JG   tail2
	VMOVDQU (SI)(AX*1), Y0
	VPCMPEQB Y1, Y0, Y2
	VPMOVMSKB Y2, BX
	TESTL BX, BX
	JZ    next2

cbits2:
	BSFL BX, DI
	MOVQ AX, R8
	ADDQ DI, R8
	MOVQ R8, R9
	ADDQ $2, R9
	CMPQ R9, CX
	JG   clearbit2
	CMPW (SI)(R8*1), R11
	JE   found2_r8
clearbit2:
	MOVL BX, R10
	DECL R10
	ANDL R10, BX
	JNZ  cbits2

next2:
	ADDQ $32, AX
	JMP  loop2

tail2:
	MOVQ AX, DX
	ADDQ $2, DX
	CMPQ DX, CX
	JG   notfound2
	CMPW (SI)(AX*1), R11
	JE   found2_ax
	INCQ AX
	JMP  tail2

found2_ax:
	VZEROUPPER
	MOVQ AX, ret+16(FP)
	RET
found2_r8:
	VZEROUPPER
	MOVQ R8, ret+16(FP)
	RET
notfound2:
	VZEROUPPER
	MOVQ $-1, ret+16(FP)
	RET
