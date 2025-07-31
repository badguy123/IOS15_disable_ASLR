# IOS15_disable_ASLR
iphone 6s Plus IOS15.8.4 disable ASLR

https://github.com/checkra1n/PongoOS


# Usage

[this repo](https://bbs.kanxue.com/thread-287808.htm) will help you.

disassemble address

    pongoOS> dis 8048c96e4 10
    0x8048c96e4  E8 67 00 A9 0x8048c96e4:	stp		x8, x25, [sp]
    0x8048c96e8  E0 23 40 F9 0x8048c96e8:	ldr		x0, [sp, #0x40]
    0x8048c96ec  E1 03 15 AA 0x8048c96ec:	mov		x1, x21
    0x8048c96f0  E2 03 18 AA 0x8048c96f0:	mov		x2, x24
    0x8048c96f4  E4 03 1A AA 0x8048c96f4:	mov		x4, x26
    0x8048c96f8  E5 03 1B AA 0x8048c96f8:	mov		x5, x27
    0x8048c96fc  06 00 80 52 0x8048c96fc:	mov		w6, #0
    0x8048c9700  50 00 00 94 0x8048c9700:	bl		#0x8048c9840
    0x8048c9704  A0 00 00 34 0x8048c9704:	cbz		w0, #0x8048c9718
    0x8048c9708  F3 03 00 AA 0x8048c9708:	mov		x19, x0


hexdump address

    pongoOS> hd 0x4046dd658 50
    0x4046dd658: 88 a1 0b 1b 08 05 00 11 08 00 80 d2 ea 13 40 f9 ..............@.
    0x4046dd668: 27 01 0a 8b 03 00 00 14 08 00 80 d2 07 00 80 d2 '...............
    0x4046dd678: 89 d0 ff 90 29 81 02 91 20 05 40 ad 22 0d 41 ad ....)... .@.".A.
    0x4046dd688: 22 0f 01 ad 20 07 00 ad 20 05 42 ad 22 0d 43 ad "... ... .B.".C.
    0x4046dd698: 22 0f 03 ad 20 07 02 ad 20 05 44 ad 22 29 c0 3d "... ... .D.").=
