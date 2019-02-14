.syntax unified

.code 32

.global start
.section .text.start
start:
    ldr sp,=#0x81000000
    blx main
