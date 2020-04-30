---
layout:     post
title:      PatriotCTF 2020 - Give Nom Nom
date:       2020-04-29
summary:    Solution to PatriotCTF 2020 challenge "Give Nom Nom"
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

This challenge was posted late in the contest, and I had some other things I
had to take care of at the time. So in usual form, I threw [angr][angr] at it
and, eventually, got a solve. The first part is solving a constraint system
where your input ends up getting permuted and then checked against some
constraints. The second part is where you get to run a command is fed into
`system`, of course after it has been run through the permutation as well.

# Triage

As usual, let's give it a run.

```raw
$ ./pwn_constraint 
Giv nom nom. I lik good nom nom
flag
BAD NOM NOM
```

[strings][strings] shows a base64 encoded blob
`lFtkesoc2AuJ91Xp8s3g6x10SgnwaArVWcogixFRGgrnS1GBDvL9kxr7LAhjVd05LR1qnakKtxjxRT2TFI2hTCqw90yfP2O==`.
[ltrace][ltrace] with the input of `test` shows a ton of `strlen` calls.

```raw
<clipped>
[pid 10029] [0x55710c875390] strlen("tste") = 4
[pid 10029] [0x55710c8753c4] strlen("sste") = 4
[pid 10029] [0x55710c87532f] strlen("stte") = 4
[pid 10029] [0x55710c875362] strlen("stte") = 4
[pid 10029] [0x55710c875390] strlen("stte") = 4
[pid 10029] [0x55710c8753c4] strlen("stte") = 4
[pid 10029] [0x55710c87532f] strlen("stte") = 4
[pid 10029] [0x55710c875362] strlen("stte") = 4
[pid 10029] [0x55710c875390] strlen("stte") = 4
[pid 10029] [0x55710c8753c4] strlen("stte") = 4
[pid 10029] [0x55710c87532f] strlen("stte") = 4
[pid 10029] [0x55710c875362] strlen("stte") = 4
[pid 10029] [0x55710c875390] strlen("stte") = 4
[pid 10029] [0x55710c8753c4] strlen("stee") = 4
[pid 10029] [0x55710c87532f] strlen("stet") = 4
[pid 10029] [0x55710c875362] strlen("stet") = 4
[pid 10029] [0x55710c875390] strlen("stet") = 4
[pid 10029] [0x55710c8753c4] strlen("ttet") = 4
[pid 10029] [0x55710c87532f] strlen("tset") = 4
[pid 10029] [0x55710c875362] strlen("tset") = 4
[pid 10029] [0x55710c875390] strlen("tset") = 4
[pid 10029] [0x55710c8753c4] strlen("tsst") = 4
[pid 10029] [0x55710c87532f] strlen("test") = 4
[pid 10029] [0x55710c875362] strlen("test") = 4
[pid 10029] [0x55710c875390] strlen("test") = 4
<clipped>
```

To be honest, I didn't reverse this manually too much. Looking at the control
flow and instructions, it seemed reasonable that [angr][angr] would be able to
solve this. I discovered two sections, which I solved concurrently with two
different methods.

# Constraint Check

Before you can do anything else, this binary is asking for your input, running
some permutations on it, and then checking it against what it expects as
output.

We can see the permutation by running some example data through it using
[revenge][revenge]:

```python
from revenge import Process, common, types
p = Process("./pwn_constraint")

# Grab the function you want to call
func = p.memory['pwn_constraint:0x12cf']

# Since this modifies in memory, allocate a string ahead of time
mem = p.memory.alloc_string(types.StringUTF8("ABCDEFG"))

# Run the string
func(mem.address)
# OUT: 70

# Read what it got permuted into
mem.string_utf8
# OUT: 'CEGAFBD'
```

You can play around with different inputs, but it seems to just scramble them.

The reasonable thing to do here would be to see if you can map out the input to
the output, since it's going to be deterministic. However, I just decided to
throw `angr` at it instead.

My `angr` solve script is as follows:

```python
import angr, claripy

proj = angr.Project("pwn_constraint")
base = 0x400000

# Avoid anything that goes to Bad nom nom
avoid = [base+0x14E9, base+0x154D] 
# Find my way PAST the first check, to the point where it prompts for input
# again
find = base+0x158B

# 96 based on the strlen check at the beginning
flag = claripy.BVS('flag', 8*96)

# Null terminate my flag
stdin = angr.SimFile('stdin', claripy.Concat(flag, 0))

state = proj.factory.entry_state(stdin=stdin, add_options=angr.options.unicorn)

# THIS IS IMPORTANT! See notes below for why.
state.libc.buf_symbolic_bytes = 128

# Tell angr that my flag should have no nulls and no newlines
for i in range(96):
    state.add_constraints(flag.get_byte(i) != 0, flag.get_byte(i) != 10)

simgr = proj.factory.simgr(state)

# go find it!
simgr.explore(find=find, avoid=avoid)
```

The key to this working is the step `state.libc.buf_symbolic_bytes = 128`. This
is because `angr` needs to set some reasonable defaults for how big things can
be. They do this to trade performance and completeness. In this case, however,
their default was too small. When you run the above script without that line,
you get `unsat`. As of writing, the default size for `buf_symbolic_bytes` is
60.

After kicking off `angr`, I decided to `revenge` to brute force a smaller
search space to find `/bin/sh`, which I would use once I got past the first
constraint.

# System Constraint

Assuming that I would eventually get past the first constraint check, I needed
to have something to give to `system` that would allow me to get the flag.
Since I wasn't actually reversing the permutation, I decided to just brute
force something small, such as `/bin/sh`.

To brute force this, I used [revenge][revenge], as follows:

```python
#!/usr/bin/env python

from revenge import Process, common, types
import itertools

# This function simply runs the permutation function against some given input
# and returns the output
def try_permute(inp, mem): 
    mem.string_utf8 = inp 
    do_permute(mem) 
    return mem.string_utf8

p = Process("./pwn_constraint")

do_permute = p.memory['pwn_constraint:0x12CF'] 

# Just allocate a block of memory to mess with
mem = p.memory.alloc(128)

target = "/bin/sh"

# Brute force the answer by trying all permutations
for perm in itertools.permutations(target): 
    x = "".join(perm) 
    if try_permute(x, mem) == target: 
        print("Winner: " + x) 
        break 

# ns/hb/i
```

The script took a few minutes to run and find that `ns/hb/i` would get me what
I wanted.

# Final

The `angr` script probably took an hour or so to complete. It also found a
solution that worked but was likely not the intended solution given that most
of it was not ascii printable.

Non ascii wasn't really an issue since it did validate, so I wrote that answer
to disk and used `cat` and piping to communicate with the binary:

```bash
(cat win.bin; echo ns/hb/i; cat -) | nc chal.pctf.competitivecyber.club 5555
cat ./gmu/patriotCTF/pwn_constraint/flag_dir/flag.txt
pctf{f1b0N4Cc1_4nD_A_sHuffL3_n0m_n0m_n0m}
```

# Downloads
- [pwn_constraint.zip](https://github.com/NoTeamName/CTF2020/raw/master/PatriotCTF/rev/give-nom-nom/pwn_constraint.zip)

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
