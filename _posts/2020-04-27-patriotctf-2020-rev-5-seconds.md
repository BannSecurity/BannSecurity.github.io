---
layout:     post
title:      PatriotCTF 2020 - 5 Seconds
date:       2020-04-27
summary:    Solution to PatriotCTF 2020 challenge "5 Seconds"
categories: writeups
thumbnail:  PatriotCTF
tags:
 - patriotctf
 - 2020
 - writeup
 - reverse
 - angr
---

5-seconds was a reversing challenge that required you to identify why your flag
was not being checked, understand signal handlers and figure out how to force
execution to the checking function. Finally, you need to reverse the checking
function itself.

# Solution Overview

1. Discover installed signal handler and get execution to check the flag
1. Use [angr][1] to generate the flag.

# Finding the Signal Handler

Start off with a quick file check:

```raw
i_love_controlling_C: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=5d030cc8d0ce25a3ef2169d449363d682170c296, for GNU/Linux 3.2.0, stripped
```

Give it a basic run:

```raw
$ ./i_love_controlling_C 
Usage: ./i_love_controlling_C <flag>

$ ./i_love_controlling_C test
C'mon, I gave you a whole 5 seconds! You weren't quick enough!!
```

So clearly it's waiting for something. Running [ltrace][2] on it, we can see
that it's registering a [sigaction][3] on SIGINT:

```raw
sigaction(SIGINT, { 0x5623b7cd3195, <>, 0, 0 }
```

In short, this indicates that if the system were to recieve a SIGINT (for
instance, from a ctrl-c), then it would handle that signal by calling a
specific function.

We can see pseudo-source in Ghidra:

```c
void sigint_handler(void)

{
  do_check_flag();
  puts("\nCorrect!");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

The `do_check_flag` function is more interesting.

```c

void do_check_flag(void)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = pFlag;
  iVar2 = strncmp("pctf{",pFlag,5);
  if ((iVar2 != 0) || (pcVar1[0x16] != '}')) {
    puts("\nNope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if ((pcVar1[8] != 'N') || (pcVar1[8] != pcVar1[0xe])) {
    puts("\nNope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if ((((int)pcVar1[7] + 1 != (int)pcVar1[0xf]) || ((int)pcVar1[7] + -2 != (int)pcVar1[0xc])) ||
     (pcVar1[0xf] != '4')) {
    puts("\nNope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (pcVar1[5] != 'a') {
    puts("\nNope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if ((pcVar1[10] == pcVar1[0x12]) && (pcVar1[10] == '_')) {
    if (pcVar1[0x15] != 'n') {
      puts("\nNope!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if (((int)pcVar1[0x14] - (int)pcVar1[0x11] != 2) || (pcVar1[0x14] != 'U')) {
      puts("\nNope!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if (((int)pcVar1[6] + 2 != (int)pcVar1[9]) || ((int)pcVar1[9] != (int)pcVar1[0x12] + 0x15)) {
      puts("\nNope!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if ((((pcVar1[0xb] == '5') && (pcVar1[0xd] == 'g')) && (pcVar1[0x10] == 'l')) &&
       (pcVar1[0x13] == 'f')) {
      return;
    }
    puts("\nNope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("\nNope!");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

At this point, you could definitely reverse this manually. However, because I'm
lazy, I decided to ask [angr][1] to do it for me.

Since angr's solution is strait forward, I'll simply provide that here with
some comments inline:

```python
import angr, claripy

proj = angr.Project("i_love_controlling_C")

# angr default base
base = 0x400000

# Setup a state that starts at our flag validation function
state = proj.factory.call_state(0x1C5C+base)

# We want to find the "success" address
find = base+0x1EDB
simgr = proj.factory.simgr(state)

# Explore until we found something
simgr.explore(find=find) 

# Our virtual bytes end up at 0
s = simgr.found[0]
s.solver.eval(s.memory.load(0, 2048), cast_to=bytes)
# pctf{ar3Nt_51gN4lS_fUn}
```

# Downloads
- [5-seconds.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/rev/5-seconds/5-seconds.zip)

[1]: https://angr.io/
[2]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[3]: http://man7.org/linux/man-pages/man2/sigaction.2.html
