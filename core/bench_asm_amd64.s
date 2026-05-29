#include "textflag.h"

// func benchAsmStringHash(s string) uint64
TEXT ·benchAsmStringHash(SB), NOSPLIT, $0-24
	MOVQ	s+0(FP), SI
	MOVQ	s+8(FP), CX
	MOVQ	$14695981039346656037, AX
	MOVQ	$1099511628211, DX
	TESTQ	CX, CX
	JZ	sh_done
sh_loop:
	MOVBQZX	(SI), BX
	XORQ	BX, AX
	IMULQ	DX, AX
	INCQ	SI
	DECQ	CX
	JNZ	sh_loop
sh_done:
	MOVQ	AX, ret+16(FP)
	RET

// func benchAsmEqualFoldASCII(a, b string) bool
TEXT ·benchAsmEqualFoldASCII(SB), NOSPLIT, $0-33
	MOVQ	a+0(FP), SI
	MOVQ	a+8(FP), CX
	MOVQ	b+16(FP), DI
	MOVQ	b+24(FP), DX
	CMPQ	CX, DX
	JNE	ef_ne
	TESTQ	CX, CX
	JZ	ef_eq
	LEAQ	·asciiLower(SB), R8
ef_loop:
	MOVBQZX	(SI), AX
	MOVB	(R8)(AX*1), AX
	MOVBQZX	(DI), BX
	MOVB	(R8)(BX*1), BX
	CMPB	AX, BX
	JNE	ef_ne
	INCQ	SI
	INCQ	DI
	DECQ	CX
	JNZ	ef_loop
ef_eq:
	MOVB	$1, ret+32(FP)
	RET
ef_ne:
	MOVB	$0, ret+32(FP)
	RET

// func benchAsmValidateHost(host string) bool
TEXT ·benchAsmValidateHost(SB), NOSPLIT, $0-17
	MOVQ	host+0(FP), SI
	MOVQ	host+8(FP), CX
	LEAQ	·badHostChar(SB), R8
	TESTQ	CX, CX
	JZ	vh_valid
vh_loop:
	MOVBQZX	(SI), AX
	CMPB	(R8)(AX*1), $0
	JNE	vh_invalid
	INCQ	SI
	DECQ	CX
	JNZ	vh_loop
vh_valid:
	MOVB	$1, ret+16(FP)
	RET
vh_invalid:
	MOVB	$0, ret+16(FP)
	RET

// func benchAsmParseUint(s string) (int, bool)
TEXT ·benchAsmParseUint(SB), NOSPLIT, $0-25
	MOVQ	s+0(FP), SI
	MOVQ	s+8(FP), CX
	LEAQ	·digitVal(SB), R8
	XORQ	AX, AX
	TESTQ	CX, CX
	JZ	pu_fail
pu_loop:
	MOVBQZX	(SI), DX
	MOVBQZX	(R8)(DX*1), DX
	CMPB	DL, $0xFF
	JE	pu_fail
	IMULQ	$10, AX
	ADDQ	DX, AX
	INCQ	SI
	DECQ	CX
	JNZ	pu_loop
	MOVQ	AX, ret+16(FP)
	MOVB	$1, ret+24(FP)
	RET
pu_fail:
	MOVQ	$0, ret+16(FP)
	MOVB	$0, ret+24(FP)
	RET

// func benchAsmContainsCRLF(s string) bool
TEXT ·benchAsmContainsCRLF(SB), NOSPLIT, $0-17
	MOVQ	s+0(FP), SI
	MOVQ	s+8(FP), CX
	TESTQ	CX, CX
	JZ	cr_no
cr_loop:
	MOVBQZX	(SI), AX
	CMPB	AL, $0x0D
	JE	cr_yes
	CMPB	AL, $0x0A
	JE	cr_yes
	INCQ	SI
	DECQ	CX
	JNZ	cr_loop
cr_no:
	MOVB	$0, ret+16(FP)
	RET
cr_yes:
	MOVB	$1, ret+16(FP)
	RET

// func benchAsmHuffmanLen(s string) int
TEXT ·benchAsmHuffmanLen(SB), NOSPLIT, $0-24
	MOVQ	s+0(FP), SI
	MOVQ	s+8(FP), CX
	LEAQ	·huffBitLen(SB), R8
	XORQ	AX, AX
	TESTQ	CX, CX
	JZ	hl_done
hl_loop:
	MOVBQZX	(SI), DX
	MOVWQZX	(R8)(DX*2), DX
	ADDQ	DX, AX
	INCQ	SI
	DECQ	CX
	JNZ	hl_loop
hl_done:
	ADDQ	$7, AX
	SHRQ	$3, AX
	MOVQ	AX, ret+16(FP)
	RET

// func benchAsmPathQuickHash(s string) uint32
TEXT ·benchAsmPathQuickHash(SB), NOSPLIT, $0-20
	MOVQ	s+0(FP), SI
	MOVL	s+8(FP), CX
	MOVL	$0x9E3779B9, R9
	CMPL	CX, $2
	JL	pqh_short
	MOVL	CX, DX
	MOVBQZX	1(SI), BX
	XORL	BX, DX
	IMULL	R9, DX
	DECL	CX
	MOVBQZX	(SI)(CX*1), BX
	INCL	CX
	XORL	BX, DX
	IMULL	R9, DX
	CMPL	CX, $4
	JL	pqh_nomed
	MOVL	CX, R8
	SHRL	$1, R8
	MOVBQZX	(SI)(R8*1), BX
	XORL	BX, DX
	IMULL	R9, DX
pqh_nomed:
	ORL	$0x80000000, DX
	MOVL	DX, ret+16(FP)
	RET
pqh_short:
	MOVL	CX, AX
	IMULL	R9, AX
	ORL	$0x80000000, AX
	MOVL	AX, ret+16(FP)
	RET
