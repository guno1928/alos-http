//go:build alos_asm

#include "textflag.h"

// func plainEncodeUserDataASM(op uint8, connIndex int, generation uint16) uint64
TEXT ·plainEncodeUserDataASM(SB), NOSPLIT, $0-32
	MOVBQZX op+0(FP), AX
	SHLQ    $56, AX
	MOVWQZX generation+16(FP), CX
	SHLQ    $32, CX
	ORQ     CX, AX
	MOVL    connIndex+8(FP), DX
	ORQ     DX, AX
	MOVQ    AX, ret+24(FP)
	RET
