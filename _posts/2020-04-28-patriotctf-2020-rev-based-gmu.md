---
layout:     post
title:      PatriotCTF 2020 - Based GMU
date:       2020-04-28
summary:    Solution to PatriotCTF 2020 challenge "Based GMU"
categories: writeups
thumbnail:  PatriotCTF
tags:
 - patriotctf
 - 2020
 - writeup
 - reverse
 - radare2
 - ghidra
---

This challenge was an ELF reversing challenge. You needed to discover how your
input was being transformed into base64, find the correct output in the binary,
and identify that there was a 3-byte repeated xor being performed on your input
after it was base64 encoded.

# Triage

Lets start out by running the binary:

```raw
$ ./based_gmu 
No key given!
Usage: ./reversing1 <key>
Exiting.

$ ./based_gmu myflag
Invalid key. Byeeeeee
```

Running [ltrace][ltrace] doesn't show much aside from some `strlen` calls.
Opening the binary in [ghidra][ghidra], I'll extract the releavant portions
here.

First off, we can see a length check:

```c
iKeyLen = strlen(argv[1]);
if (0x31 < iKeyLen) {
    puts("Key incorrect. Exiting.");
    exit(1);
}
```

From that we can assume an input length of 49. While that may or may not be the
actual length, we know the authors put bounds for a reason, so we'll assume
that.

Next, we notice that our input is being fed to something called
`base64_encode`:

```c
iKeyLen = strlen(argv[1]);
*psVar1 = (iKeyLen / 3) * 4;
iKeyLen = strlen(argv[1]);
pBase64Input = base64_encode(pMyInput,iKeyLen,psVar1);
```

The assumption here is that my input will be base64 encoded and returned as a
new pointer. To verify this, we'll run a quick test in [radare2][radare2].

```raw
$ r2 ./based_gmu
 -- (gdb) ^D
[0x00001080]> ood myflag
Process with PID 2933 started...
= attach 2933 2933
File dbg:///home/angr/work/ctf/patriot2020/rev/based-gmu/based_gmu  myflag reopened in read-write mode
2933
[0x7ffa93d4b090]> dcu sym.base64_encode 
Continue until 0x557b67b39374 using 1 bpsize
hit breakpoint at: 557b67b39374
[0x557b67b39374]> dcr
hit breakpoint at: 557b67b393c1
[0x557b67b395b6]> drr
role reg     value            ref
―――――――――――――――――――――――――――――――――
R0   rax     557b68916280      ([heap]) heap R W 0x6e4647626d6c5862 (bXlmbGFn) -->  ascii ('b')
     rbx     0                 0
A3   rcx     0                 0
A2   rdx     0                 0
A4   r8      2                 2
A5   r9      0                 0
     r10     557b68916010      ([heap]) heap R W 0x0 -->  0
     r11     0                 0
     r12     557b67b39080      (/home/angr/work/ctf/patriot2020/rev/based-gmu/based_gmu) (.text) program R X 'xor ebp, ebp' 'based_gmu'
     r13     7ffc63b13d80      ([stack]) stack R W 0x2 -->  2
     r14     0                 0
     r15     0                 0
A1   rsi     0                 0
A0   rdi     557b68916290      ([heap]) heap R W 0x0 -->  0
SP   rsp     7ffc63b13c38      ([stack]) stack R W 0x557b67b39263 -->  (/home/angr/work/ctf/patriot2020/rev/based-gmu/based_gmu) (.text) program R X 'mov qword [rbp - 0x20], rax' 'based_gmu'
BP   rbp     7ffc63b13ca0      ([stack]) stack R W 0x557b67b395c0 -->  (/home/angr/work/ctf/patriot2020/rev/based-gmu/based_gmu) (.text) sym.__libc_csu_init program R X 'push r15' 'based_gmu'
PC   rip     557b67b395b6      (/home/angr/work/ctf/patriot2020/rev/based-gmu/based_gmu) (.text) program R X 'ret' 'based_gmu'
     cs      33                51 ascii ('3')
     rflags  246               582
SN   orax    ffffffffffffffff 
     ss      2b                43 ascii ('+')
     fs_base 7ffa93f5f4c0      (unk1) R W 0x7ffa93f5f4c0
     gs_base 0                 0
     ds      0                 0
     es      0                 0
     fs      0                 0
     gs      0                 0

```

We can see that the `base64_encode` function returns `bXlmbGFn` which is indeed
`myflag` in base64. With that, we'll assume this function performs as
advertised.

# Comparison Routine

Now that we know our input gets base64 encoded, we can move on to the
comparison routine.

```c
*(undefined4 *)pXorKey = 0x756d67;
bufExpectedOutput = 0x5e131b3f323b2832;
local_50 = 0x5630173f202b2214;
local_48 = 0xd0a572f0b214535;
local_40 = 0x240b573c2535;
while( true ) {
if (0x1d < iKeyLenCounter) {
  puts("Authenticated.");
  return 0;
}
cMyInputXord = *(byte *)((long)pXorKey + (long)(iRepeatedXorKey % 3)) ^
               *(byte *)((long)pBase64Input + (long)iKeyLenCounter);
if (cMyInputXord != *(byte *)((long)&bufExpectedOutput + (long)iKeyLenCounter)) break;
iKeyLenCounter = iKeyLenCounter + 1;
iRepeatedXorKey = iRepeatedXorKey % 3 + 1;
}
```

In the while loop, we see a check if our counter is greater than 0x1d. If so,
it claims we authenticated. This is basically a char by char validation
function, and so we know our flag must be 29 chars in length.

The jumble of addition and xoring is simply a repeated [xor cipher][xor
cipher] of key length 3. The comparison is being made byte by byte from the
chars that were written to the stack.

# Solving the flag

With all this in mind, we know all we have to do is perform the repeated xor
against the expected output, then base64 decode the result.

```python
xor("umg"[::-1], b"^\x13\x1B?2;(2"[::-1] + b'V0\x17? +"\x14'[::-1] + b"5E!\v/W\n\r5%<W\v$")
# b'UENURnt3aEFUXzE1X0FfZ0gxRHI0fQ'
b64decode("UENURnt3aEFUXzE1X0FfZ0gxRHI0fQ")
# PCTF{whAT_15_A_gH1Dr4}
```

# Downloads
- [based_gmu.zip](https://github.com/NoTeamName/CTF2020/blob/master/PatriotCTF/rev/based_gmu/based_gmu.zip?raw=true)

[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[ghidra]: https://ghidra-sre.org/
[radare2]: https://rada.re/n/
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
