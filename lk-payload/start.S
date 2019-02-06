.syntax unified

.code 32

.global start
.section .text.start
start:
    ldr sp,=#0x8BB00000
    blx main
