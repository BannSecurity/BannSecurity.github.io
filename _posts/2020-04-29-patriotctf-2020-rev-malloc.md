---
layout:     post
title:      PatriotCTF 2020 - Malloc
date:       2020-04-29
summary:    Solution to PatriotCTF 2020 challenge "Malloc"
categories: writeups
thumbnail:  PatriotCTF
tags:
 - patriotctf
 - 2020
 - writeup
 - reverse
 - radare2
 - ghidra
 - revenge
---

This challenge was interesting in that I found the flag more or less by
accident. It was also a good example of using my pet project [revenge][revenge]
to aid in reversing.

My solution steps involved identifying that [malloc][malloc] was being run a
bunch, using [revenge][revenge] to trace the output of each malloc, then
accidentally discovering that the flag was ascii art.

# Triage

As usual, let's give it a run.

```raw
$ ./malloc 
I think you missed the flag
```

Not much to go on there. [strings][strings] doesn't show anything of interest.
Running [ltrace][ltrace] shows a ton of `malloc` calls:

```raw
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c360
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c380
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c3a0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c3c0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c3e0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c400
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c420
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c440
[pid 8868] [0x556dcade1988] malloc(64) = 0x556dcc26c460
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c4b0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c4d0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c4f0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c510
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c530
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c550
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c570
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c590
[pid 8868] [0x556dcade1988] malloc(64) = 0x556dcc26c5b0
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c600
[pid 8868] [0x556dcade174d] malloc(8)  = 0x556dcc26c620
```

A quick peek at the decompiled output:

```c
int main(void)
{
  int iVar1;
  undefined8 *puVar2;
  void *pvVar3;
  void *pvVar4;
  int local_38;
  int local_34;
  
  puVar2 = (undefined8 *)malloc(0xa8);
  *puVar2 = 0x201010;
  puVar2[1] = 0x201018;
  puVar2[2] = 0x201020;
  puVar2[3] = 0x201028;
  puVar2[4] = 0x201030;
  puVar2[5] = 0x201038;
  puVar2[6] = 0x201040;
  puVar2[7] = 0x201048;
  puVar2[8] = 0x201050;
  puVar2[9] = 0x201058;
  puVar2[10] = 0x201060;
  puVar2[0xb] = 0x201068;
  puVar2[0xc] = 0x201070;
  puVar2[0xd] = 0x201078;
  puVar2[0xe] = 0x201080;
  puVar2[0xf] = 0x201088;
  puVar2[0x10] = 0x201090;
  puVar2[0x11] = 0x201098;
  puVar2[0x12] = 0x2010a0;
  puVar2[0x13] = 0x2010a8;
  puVar2[0x14] = 0x2010b0;
  local_38 = 0;
  while (local_38 < 0x15) {
    pvVar3 = malloc((long)DAT_002010b8 << 3);
    local_34 = 0;
    while (local_34 < DAT_002010b8) {
      pvVar4 = FUN_00000730(*(byte *)((long)local_34 + puVar2[local_38]));
      *(void **)((long)local_34 * 8 + (long)pvVar3) = pvVar4;
      local_34 = local_34 + 1;
    }
    *(void **)(puVar2 + local_38) = pvVar3;
    local_38 = local_38 + 1;
  }
  iVar1 = puts("I think you missed the flag");
  return iVar1;
}
```

We can see that we're looping and performing `malloc` calls. My initial guess
was that the flag would be hidden inside of one of those calls. I was sorta
right and sorta wrong..

# Tracing the Function

To get more information about what was going on here, I decided to use my
personal tool [revenge][revenge]. You could definitely do this sort of tracing
in many other ways, but I chose to use `revenge`.

The function that's being called over and over is at `0x730`. I was interested
in what it was returning. For brevity, I'll show my enumeration script with
comments inline.

```python
#!/usr/bin/env python

from revenge import Process, common, types

# Standard loading up an elf file
p = Process("./malloc")

# This is the function I'd like to trace
thing = p.memory['malloc:0x730']

# I will keep return values in here
msgs = []

# This function will get called every time the function is run
def catch_message(x,y): 
    global msgs 
    # Simply append the message so we can look at it later
    msgs.append(x['payload'])

# Setting up my function for tracing
thing.return_type = types.Pointer

# Only one argument, and it's technically a byte, but int8 works
thing.argument_types = types.Int8

# Every time we get a message, I want catch_message to be notified
thing.replace_on_message = catch_message

# Here is where I'm actually replacing the function with my js (via frida)
# The js simply calls the function, reads the return as a pointer to a string,
# and sends that string back
thing.replace = """function (s) { var ret=original(s); send(ret.readUtf8String()); return ret;}"""

# This will cause binary execution to continue
p.memory[p.entrypoint].breakpoint = False
```

Wouldn't you know, to my surprise when I looked at the results of my trace, i
saw this:

```python
In [3]: msgs
Out[3]: 
[' ###### ',
 ' #     #',
 ' #     #',
 ' ###### ',
 ' #      ',
 ' #      ',
 ' #      ',
 '        ',
 '  ##### ',
 ' #     #',
 ' #      ',
 ' #      ',
 ' #      ',
 ' #     #',
 '  ##### ',
 '        ',
 ' #######',
 '    #   ',
 '    #   ',
 '    #   ',
 '    #   ',
 '    #   ',
 '    #   ',
 '        ',
# clipped
```

Well obviously the game was up now. Clearly all I had to do was combine the
lines assuming an 8 length array to get the flag:

```python
out = ['']*8

for i in range(0, len(msgs), 8):
    for j in range(8):
        out[j] += msgs[i+j]

[' ######   #####  ####### #######   ### ####### #     #         #     # #     #         ####### #     # #######  #####          #     # #     # ######  ####### #   ##   ',
 ' #     # #     #    #    #        #    #     # #  #  #         ##   ##  #   #          #        #   #  #       #     #         #     # #     # #     #    #          #  ',
 ' #     # #          #    #        #    #     # #  #  #         # # # #   # #           #         # #   #       #               #     # #     # #     #    #          #  ',
 ' ######  #          #    #####   ##    #     # #  #  #         #  #  #    #            #####      #    #####    #####          ####### #     # ######     #          ## ',
 ' #       #          #    #        #    #     # #  #  #         #     #    #            #          #    #             #         #     # #     # #   #      #          #  ',
 ' #       #     #    #    #        #    #     # #  #  #         #     #    #            #          #    #       #     #         #     # #     # #    #     #          #  ',
 ' #        #####     #    #         ### #######  ## ##          #     #    #            #######    #    #######  #####          #     #  #####  #     #    #    #   ##   ',
 '                                                       #######                 #######                                 #######                                          ']

# The above likely won't display well...
# PCTF{OW_MY_EYES_HURT}
```

Score one for accidental solve.

# Downloads
- [malloc.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/rev/malloc/malloc.zip)

[angr]: http://angr.io/
[bash]: https://www.gnu.org/software/bash/
[fork]: http://man7.org/linux/man-pages/man2/fork.2.html
[ghidra]: https://ghidra-sre.org/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[malloc]: http://man7.org/linux/man-pages/man3/malloc.3.html
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[radare2]: https://rada.re/n/
[revenge]: https://revenge.readthedocs.io/en/latest/
[strings]: http://man7.org/linux/man-pages/man1/strings.1.html
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
