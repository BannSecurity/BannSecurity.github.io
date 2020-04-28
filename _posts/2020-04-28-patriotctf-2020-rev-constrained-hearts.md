---
layout:     post
title:      PatriotCTF 2020 - Constrained Hearts
date:       2020-04-28
summary:    Solution to PatriotCTF 2020 challenge "Constrained Hearts"
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

This challenge involved identifying how user input was being read in from a
file, determining where the validation function was, and using [angr][angr] to solve
it.

# Triage

As usual, let's give it a run.

```raw
$ ./hearts blerg
Failed to open blerg

$ echo "hello" > hello

$ ./hearts hello
Close but no Cigar
```

An [ltrace][ltrace] simply confirms that we're reading in the file but provides
no more useful information.

Opening in [ghidra][ghidra] we see it apparently reads in the file into memory:

```c
if (argc < 2) {
    printf("USAGE: %s file\n",*argv);
}
uVar1 = read_file(argv[1],bufMyInput,0x20);
```

To quick validate that it's reading in our file, we can use [radare2][radare2].

```raw
$ r2 ./hearts
 -- Charlie! We are here.
[0x00000760]> ood hello
Process with PID 4132 started...
= attach 4132 4132
File dbg:///home/angr/work/ctf/patriot2020/rev/Constrained-Hearts/hearts  hello reopened in read-write mode
4132
[0x7f7a4bf42090]> dcu sym.read_file
Continue until 0x564d7e00d86a using 1 bpsize
hit breakpoint at: 564d7e00d86a
[0x564d7e00d86a]> dr rsi
0x7fffc143b480
[0x564d7e00d86a]> dcr
hit breakpoint at: 564d7e00d890
hit breakpoint at: 564d7e00d8d2
hit breakpoint at: 564d7e00d8e9
[0x564d7e00d8ef]> ps @ 0x7fffc143b480
hello
```

So we've confirmed that our input was indeed read into the buffer. The next few
lines show us where our input is going:

```c
if ((int)uVar1 == 0) {
  uVar2 = check_file(bufMyInput);
  if ((int)uVar2 == 0) {
    puts(bufMyInput);
    puts("Nice Job!");
    iRetCode = 0;
  }
  else {
    puts("Close but no Cigar");
    iRetCode = 1;
  }
}
```

So our input is going to `check_file`.

# Recovering the flag

The `check_file` function is a bit of a mess of code. However, since all the
code is relatively strait forward, this is solvable with [angr][angr].

```python
#!/usr/bin/env python

import angr, claripy

proj = angr.Project("./hearts")
base = 0x400000

# Size determined from "iMyInputLen != 0x1a" check
flag = claripy.BVS('flag', 8*26)

# Create a state that starts at the check
state = proj.factory.call_state(base+0x8F0, [flag])

# Flag shouldn't have nulls or newlines
for i in range(26):
    state.add_constraints(flag.get_byte(i) != 0, flag.get_byte(i) != 10)

simgr = proj.factory.simgr(state)
simgr.explore(find=base+0xCBC, avoid=base+0xCC1)
s.solver.eval(flag, cast_to=bytes)
# b'pctf{Hearts_ ut_4_Hara@be}'
```

As it turns out, this binary had unintended solutions, so that wasn't exactly
the flag they were looking for but still counted.

# Downloads
- [hearts.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/rev/constrained_hearts/hearts.zip)

[angr]: http://angr.io/
[bash]: https://www.gnu.org/software/bash/
[ghidra]: https://ghidra-sre.org/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[radare2]: https://rada.re/n/
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
