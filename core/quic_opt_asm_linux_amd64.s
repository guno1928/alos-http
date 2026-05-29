#include "textflag.h"

TEXT ·quicParseVarintASM(SB), NOSPLIT, $0-40
	MOVQ	data_base+0(FP), DI
	MOVQ	data_len+8(FP), SI
	TESTQ	SI, SI
	JZ	pv_zero
	MOVBLZX	(DI), AX
	MOVQ	AX, CX
	SHRQ	$6, CX
	TESTQ	CX, CX
	JZ	pv_prefix0
	CMPQ	CX, $1
	JE	pv_prefix1
	CMPQ	CX, $2
	JE	pv_prefix2
	JMP	pv_prefix3

pv_prefix0:
	ANDQ	$0x3f, AX
	MOVQ	AX, ret+24(FP)
	MOVQ	$1, ret1+32(FP)
	RET

pv_prefix1:
	CMPQ	SI, $2
	JL	pv_zero
	ANDQ	$0x3f, AX
	SHLQ	$8, AX
	MOVBLZX	1(DI), CX
	ORQ	CX, AX
	MOVQ	AX, ret+24(FP)
	MOVQ	$2, ret1+32(FP)
	RET

pv_prefix2:
	CMPQ	SI, $4
	JL	pv_zero
	ANDQ	$0x3f, AX
	SHLQ	$24, AX
	MOVBLZX	1(DI), CX
	SHLQ	$16, CX
	ORQ	CX, AX
	MOVBLZX	2(DI), CX
	SHLQ	$8, CX
	ORQ	CX, AX
	MOVBLZX	3(DI), CX
	ORQ	CX, AX
	MOVQ	AX, ret+24(FP)
	MOVQ	$4, ret1+32(FP)
	RET

pv_prefix3:
	CMPQ	SI, $8
	JL	pv_zero
	MOVQ	(DI), AX
	BSWAPQ	AX
	MOVQ	$0x3fffffffffffffff, CX
	ANDQ	CX, AX
	MOVQ	AX, ret+24(FP)
	MOVQ	$8, ret1+32(FP)
	RET

pv_zero:
	MOVQ	$0, ret+24(FP)
	MOVQ	$0, ret1+32(FP)
	RET

TEXT ·quicVarintLenASM(SB), NOSPLIT, $0-16
	MOVQ	v+0(FP), AX
	CMPQ	AX, $64
	JGE	vl_check2
	MOVQ	$1, ret+8(FP)
	RET
vl_check2:
	CMPQ	AX, $16384
	JGE	vl_check4
	MOVQ	$2, ret+8(FP)
	RET
vl_check4:
	CMPQ	AX, $1073741824
	JGE	vl_ret8
	MOVQ	$4, ret+8(FP)
	RET
vl_ret8:
	MOVQ	$8, ret+8(FP)
	RET

TEXT ·quicIsLongHeaderASM(SB), NOSPLIT, $0-25
	MOVQ	data_len+8(FP), AX
	TESTQ	AX, AX
	JZ	ilh_false
	MOVQ	data_base+0(FP), DI
	TESTB	$0x80, (DI)
	JZ	ilh_false
	MOVB	$1, ret+24(FP)
	RET
ilh_false:
	MOVB	$0, ret+24(FP)
	RET

TEXT ·quicReadPacketNumberASM(SB), NOSPLIT, $0-40
	MOVQ	data_base+0(FP), DI
	MOVQ	pnLen+24(FP), SI
	XORQ	AX, AX
	XORQ	CX, CX
rpn_loop:
	CMPQ	CX, SI
	JGE	rpn_done
	SHLQ	$8, AX
	MOVBLZX	(DI)(CX*1), DX
	ORQ	DX, AX
	INCQ	CX
	JMP	rpn_loop
rpn_done:
	MOVQ	AX, ret+32(FP)
	RET

TEXT ·quicDecodePacketNumberASM(SB), NOSPLIT, $0-32
	MOVQ	truncated+0(FP), R8
	MOVQ	truncatedLen+8(FP), R9
	MOVQ	largestAcked+16(FP), R10
	LEAQ	1(R10), R11
	MOVQ	R9, CX
	SHLQ	$3, CX
	MOVQ	$1, R12
	SHLQ	CL, R12
	MOVQ	R12, R13
	SHRQ	$1, R13
	MOVQ	R12, R14
	DECQ	R14
	MOVQ	R14, R15
	NOTQ	R15
	ANDQ	R11, R15
	ORQ	R8, R15
	MOVQ	R15, AX
	ADDQ	R13, AX
	CMPQ	AX, R11
	JG	dpn_check2
	MOVQ	$0x4000000000000000, AX
	SUBQ	R12, AX
	CMPQ	R15, AX
	JGE	dpn_check2
	LEAQ	(R15)(R12*1), AX
	MOVQ	AX, ret+24(FP)
	RET
dpn_check2:
	MOVQ	R11, AX
	ADDQ	R13, AX
	CMPQ	R15, AX
	JLE	dpn_ret_candidate
	CMPQ	R15, R12
	JL	dpn_ret_candidate
	MOVQ	R15, AX
	SUBQ	R12, AX
	MOVQ	AX, ret+24(FP)
	RET
dpn_ret_candidate:
	MOVQ	R15, ret+24(FP)
	RET

TEXT ·quicEncodePacketNumberASM(SB), NOSPLIT, $0-32
	MOVQ	pn+0(FP), AX
	MOVQ	largestAcked+8(FP), CX
	MOVQ	AX, DX
	SUBQ	CX, DX
	CMPQ	DX, $0x80
	JGE	epn_check2
	ANDQ	$0xff, AX
	MOVQ	AX, ret+16(FP)
	MOVQ	$1, ret1+24(FP)
	RET
epn_check2:
	CMPQ	DX, $0x8000
	JGE	epn_check3
	ANDQ	$0xffff, AX
	MOVQ	AX, ret+16(FP)
	MOVQ	$2, ret1+24(FP)
	RET
epn_check3:
	CMPQ	DX, $0x800000
	JGE	epn_ret4
	MOVL	$0x00ffffff, CX
	ANDQ	CX, AX
	MOVQ	AX, ret+16(FP)
	MOVQ	$3, ret1+24(FP)
	RET
epn_ret4:
	MOVL	$0xffffffff, CX
	ANDQ	CX, AX
	MOVQ	AX, ret+16(FP)
	MOVQ	$4, ret1+24(FP)
	RET

TEXT ·quicPutVarintASM(SB), NOSPLIT, $0-40
	MOVQ	dst_base+0(FP), DI
	MOVQ	v+24(FP), AX
	CMPQ	AX, $64
	JGE	pvt_put2
	MOVB	AL, (DI)
	MOVQ	$1, ret+32(FP)
	RET
pvt_put2:
	CMPQ	AX, $16384
	JGE	pvt_put4
	MOVQ	AX, CX
	ORQ	$0x4000, CX
	MOVQ	CX, DX
	SHRQ	$8, DX
	MOVB	DL, (DI)
	MOVB	CL, 1(DI)
	MOVQ	$2, ret+32(FP)
	RET
pvt_put4:
	CMPQ	AX, $1073741824
	JGE	pvt_put8
	ORQ	$0x80000000, AX
	MOVL	AX, DX
	BSWAPL	DX
	MOVL	DX, (DI)
	MOVQ	$4, ret+32(FP)
	RET
pvt_put8:
	MOVQ	$0xc000000000000000, CX
	ORQ	CX, AX
	BSWAPQ	AX
	MOVQ	AX, (DI)
	MOVQ	$8, ret+32(FP)
	RET
