---
layout:     post
title:      PatriotCTF 2020 - Fork
date:       2020-04-29
summary:    Solution to PatriotCTF 2020 challenge "Fork"
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

This challenge was one of my favorites for PatriotCTF 2020. It involved
reversing a process that spawned a subprocess using [fork][fork]. That subprocess then attached
back to the parent, unpacked some code, and actually wrote the code back into
the parent's process. Finally, the parent was resumed and executed the now
unpacked code provided by it's child.

This presented several challenges, since we are using [ptrace][ptrace] legitimately, we
can't simply remove those calls. Instead, we have to come up with a different
method to debug what's going on.

My solution ended up being to manually decrypt the encrypted code, load it in
[ghidra][ghidra] to see what was being executed, then write a couple lines of
python to reverse the flag.

# Triage

As usual, let's give it a run.

```raw
./fork
Weird, I feel like more should have happened
```

So that is actually what happened to me the first few times. Took a second for
me to realize they're using [ptrace][ptrace] and, as it turns out, ptrace can
sometimes need special permissions to run. The details are not important here,
but the short of it is, you can use the following command to temporarily enable
ptracing to work in this manner:

```bash
sudo sysctl kernel.yama.ptrace_scope=0
```

This is __not__ recommended for anything long term since it opens up some big
security problems. For more information, check out
[kernel.org](https://www.kernel.org/doc/Documentation/security/Yama.txt).

With that change made, let's look at it again:

```bash
$ ./fork
What's the password?
password
Wrong!
```

So we now get prompted for a password. But if we check [strings][strings], we
don't see any references:

```bash
strings ./fork | grep -i "password"
# no output
```

Also, if we try to run [ltrace][ltrace], we're going to immediately run into
issues. We're basically getting the original "something should have happened"
error. This is because you can only have one [ptrace][ptrace] attached at a time.

Let's open it up in [ghidra][ghidra]. We can see the fork here.

# Parent Side

```c
iForkRet = fork();
if (iForkRet != 0) {
                  /* Parent Side */
  sleep(1);
  puts("Weird, I feel like more should have happened");
  exit(0);
}
```

Comments and variable namings are my own. The parent side just has a sleep,
followed by a puts and an exit. This is further indication that there's ptrace
monkey business going on.

# Child Side

Working further down the child side:

```c
iPpid = getppid();
iPtraceRet = ptrace(PTRACE_ATTACH,(ulong)iPpid,0,0);
if (iPtraceRet < 0) {
  exit(1);
}
wait((void *)0x0);
iPtraceRet = ptrace(PTRACE_GETREGS,(ulong)iPpid,0,ptrace_regs);
if (iPtraceRet < 0) {
  exit(1);
```

Here we see the child attaching to it's parent and saving off the registers for
later setting.


```c
pMalloc0x1d2 = (uint *)malloc(0x1d2);
do_unpack_code(pMalloc0x1d2,bufPackedCode,0x1d2);
do_poke_code(iPpid,pMalloc0x1d2,bufDstAddress,0x1d2);
bufDstAddress = bufDstAddress + 2;
iPtraceRet = ptrace(PTRACE_SETREGS,(ulong)iPpid,0,ptrace_regs);
if (iPtraceRet < 0) {
  exit(1);
}
iPtraceRet = ptrace(PTRACE_CONT,(ulong)iPpid,0,0);
if (iPtraceRet < 0) {
  exit(1);
}
```

The two function calls there are after my renaming. However, what we knew
initially was that the `bufPackedCode` was some blob. We can figure out that
it's encrypted code by looking at the first function:

```c
memcpy(pMallocdSpace,bufPackedCode,(long)iSize);
iCounter = 0;
while (iCounter < iSize) {
  *(byte *)((long)pMallocdSpace + (long)iCounter) =
       ~*(byte *)((long)bufPackedCode + (long)iCounter);
  iCounter = iCounter + 1;
}
return;
```

This is a pretty strait forward unpacker. In this case, the bytes are being
negated, which is effectively an [xor cipher][xor cipher] with key `0xff`. This
will allow us to manually unpack that code section.

Take a look at the second function:

```c
long iPtraceRet;
int iCounter;
uint *pUnpackedCode_2;
long pDstAddress;

iCounter = 0;
pUnpackedCode_2 = pUnpackedCode;
pDstAddress = pDstAddress_start;
while( true ) {
  if (iSize <= iCounter) {
    return 0;
  }
  iPtraceRet = ptrace(PTRACE_POKETEXT,(ulong)iPpid,pDstAddress,(ulong)*pUnpackedCode_2);
  if (iPtraceRet < 0) break;
  iCounter = iCounter + 4;
  pUnpackedCode_2 = pUnpackedCode_2 + 1;
  pDstAddress = pDstAddress + 4;
}
```

The main thing to note here is that we're iterating over our unpacked code, and
using `POKETEXT` to write it into the parent process. This is the function that
actually changes the parent's execution.

# Unpacked Code

Now that we've done all this, let's take a look at the unpacked code. We know
the unpacked code is what is getting executed by the parent, so it is important
to understand how it works.

The following [radare2][radare2] bindings will unpack this code for us:

```python
import r2pipe
from base64 import b64decode

r2 = r2pipe.open("./fork")
func = "".join(chr(x^0xff) for x in b64decode(r2.cmd("p6e 0x1d2 @ 0x00c48")))

# 'é§\x00\x00\x00\x90f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x89|$ìH\x89t$à\x89T$è\x8b|$ìH\x8bt$à\x8bT$è¸\x00\x00\x00\x00\x0f\x05H\x89D$øH\x8bD$øÃ\x89|$ìH\x89t$à\x89T$è\x8b|$ìH\x8bt$à\x8bT$è¸\x01\x00\x00\x00\x0f\x05H\x89D$øH\x8bD$øÃ\x89|$ì\x8b|$ì¸<\x00\x00\x00\x0f\x05H\x89D$øH\x8bD$øÃWhat\'s the password?\n\x00Correct!\n\x00Wrong!\n\x00\x00\x00H\x83ì@º\x15\x00\x00\x00H\x8d5Æÿÿÿ¿\x01\x00\x00\x00èvÿÿÿ\x0f·\x05Ýÿÿÿf\x89D$ HÇD$"\x00\x00\x00\x00HÇD$*\x00\x00\x00\x00ÇD$2\x00\x00\x00\x00fÇD$6\x00\x00H¸¯¼«¹\x84Î\x91µHºÌ\x9c«Ì\x9b\xa0\x9a§H\x89\x04$H\x89T$\x08H¸Ì\x9cª\x8b\x96Ï\x91\x82H\x89D$\x10ÆD$\x18\x00H\x8dD$ º\x18\x00\x00\x00H\x89Æ¿\x00\x00\x00\x00èÕþÿÿÇD$<\x18\x00\x00\x00ÇD$8\x00\x00\x00\x00ÇD$8\x00\x00\x00\x00ë-\x8bD$8H\x98\x0f¶D\x04 \x0f¾À÷Ð\x89Â\x8bD$8H\x98\x0f¶\x04\x04\x0f¾À9Âu\x05\x83l$<\x01\x83D$8\x01\x83|$8\x17~Ì\x83|$<\x00u\x18º\t\x00\x00\x00H\x8d5üþÿÿ¿\x01\x00\x00\x00è\x96þÿÿë\x16º\x07\x00\x00\x00H\x8d5îþÿÿ¿\x01\x00\x00\x00è~þÿÿ¿\x00\x00\x00\x00è\xa0þÿÿ¸\x00\x00\x00\x00H\x83Ä@Ã'
```

In the decrypted output, we can see the text prompt, so we're on the right
path. To look at the data, let's write this back into the binary and re-load it
in ghidra.

```python
# Need to reopen fork in write-allowed mode
r2.cmd("oo+") 
# Write in the decrypted stuff
r2.cmd("w6d " + b64encode(func.encode('latin-1')).decode() + "@0x00c48") 
```

Looking at it in ghidra we get:

```c
local_20 = 0;
local_1e = 0;
local_16 = 0;
local_e = 0;
local_a = 0;
local_40 = 0xb591ce84b9abbcaf;
local_38 = 0xa79aa09bccab9ccc;
local_30 = 0x8291cf968baa9ccc;
local_28 = 0;
FUN_00000c58(0,&local_20,0x18);
local_4 = 0x18;
iCounter = 0;
while (iCounter < 0x18) {
  if ((byte)~*(byte *)((long)&local_20 + (long)iCounter) ==
      *(byte *)((long)&local_40 + (long)iCounter)) {
    local_4 = local_4 + -1;
  }
  iCounter = iCounter + 1;
}
```

We can see the loop is doing a comparison, likely of our input and expected
input. The expected input is written at local_40. With this in mind, we can now
reverse the expected flag:

```python
packed = pack("<Q", 0xb591ce84b9abbcaf) + pack("<Q", 0xa79aa09bccab9ccc) + pack("<Q", 0x8291cf968baa9ccc)
"".join(chr(x^0xff) for x in packed)
# PCTF{1nJ3cT3d_eX3cUti0n}
```

# Downloads
- [fork.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/rev/fork/fork.zip)

[angr]: http://angr.io/
[bash]: https://www.gnu.org/software/bash/
[fork]: http://man7.org/linux/man-pages/man2/fork.2.html
[ghidra]: https://ghidra-sre.org/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[radare2]: https://rada.re/n/
[strings]: http://man7.org/linux/man-pages/man1/strings.1.html
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
