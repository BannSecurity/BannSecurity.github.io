---
layout:     post
title:      Sunshine CTF 2020 - Florida Forecaster
date:       2020-11-09
summary:    Solution to Sunshine CTF 2020 challenge "Florida Forecaster"
categories: writeups
thumbnail:  SunshineCTF
tags:
 - SunshineCTF
 - 2020
 - writeup
 - pwn
 - ghidra
---

This challenge was an interesting use case of bypassing a canary. I don't
recall seeing this specific trick in any other CTFs. In short, you ended up
getting control over an exception handler by writing past the stack canary,
which would normally stop it. You then simply wait for the exception to happen
to get the flag.

# Triage

Giving this a quick run, we see it's a menu based pwn challenge.

{% highlight raw %}
$ file florida_forecaster
florida_forecaster: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=685b66c4c181f1669df6ec06174885e0b87722fc, for GNU/Linux 3.2.0, stripped

$ checksec ./florida_forecaster
[*]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

$ ./florida_forecaster 
============================
FLORIDA MAN FORECAST MACHINE
============================
1) Help
2) Test processing unit
3) Forecast
4) Exit

Choice: 1
Concerned about how Florida Man might ruin your vacation with his crazy antics?

Our proprietary machine learning wizardry analyzes conditions based on two simple forecast parameters,
informing you what to expect during your visit to our great state.

If you doubt your forecasts, feel free to run our automated* tests

* Hey, Rob, you automated those tests, right?
1) Help
2) Test processing unit
3) Forecast
4) Exit

Choice: 2
Enter test data
test
Received test data: test
Does it match (y/n)?
y
Program operating normally

1) Help
2) Test processing unit
3) Forecast
4) Exit

Choice: 3
Enter first forecast parameter (integer): 0
Enter second forecast parameter (integer): 0

A Florida man will attack a McDonalds employee for not getting a straw

1) Help
2) Test processing unit
3) Forecast
4) Exit

Choice: 4
{% endhighlight %}

If you're like me and left the program open at the prompt for over 30 seconds,
you get the following:

{% highlight raw %}
$ ./florida_forecaster
============================
FLORIDA MAN FORECAST MACHINE
============================
1) Help
2) Test processing unit
3) Forecast
4) Exit

Choice: Hey, you are taking too long
I'm only going to warn you once...
Alarm clock
{% endhighlight %}

# The Print Flag Function

Since this binary has all protections turned on, we might need to break
[ASLR][ASLR]. When I started looking through the program I had forgotten to do
a [strings][strings] run first (whoops). Instead, I opened the binary in
[ghidra][ghidra] and discovered a function that didn't seem to have any
references to it, but looked like part of the solution:

{% highlight c %}
void FUN_00101289(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_15 = '\0';
  local_14 = open("./flag.txt",0);
  if (local_14 == -1) {
    puts("Error opening flag.txt");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 != 1) break;
    putchar((int)local_15);
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
{% endhighlight %}

If I had run strings first, seeing "flag.txt" would have been a giveaway for
something i needed to look at. In any case, since this function exists, it's
clear we should likely be using it as part of our solution. We still have the
fact that this is a PIE binary and thus we need to figure out how to either
leak it's address or perform a partial overwrite.

# The Forecast

Looking at the forecast function I discovered a code path I had not taken:

{% highlight c %}
void do_forecast(void)

{
  uint iInputOne;
  uint iInputTwo;
  
  printf("Enter first forecast parameter (integer): ");
  iInputOne = do_get_input();
  printf("Enter second forecast parameter (integer): ");
  iInputTwo = do_get_input();
  if ((((int)iInputOne < 1) || (-1 < (int)iInputTwo)) || ((iInputOne ^ iInputTwo) != 0xc0c0c0c0)) {
    printf("\nA Florida man %s\n\n",
           (&PTR_s_will_attack_a_McDonalds_employe_00104020)[(int)(iInputOne ^ iInputTwo) % 10]);
  }
  else {
    printf("%p\n",FUN_00101369);
  }
  return;
}
{% endhighlight %}

Code like this should generally raise alarm bells since it's overly
complicated. Obviously they're doing something here they shouldn't be doing and
the output of the forecast will change based on very constrained inputs. Since
most of the inputs place us in the first path starting with "A Florida man",
I'm interested in the second.

The second path prints out a pointer to a function in memory! This is what we
need to be able to break ASLR. If we can get that pointer, all we need to do is
subtract it's relative offset from the start of the binary to get where the
binary's base load address is. From the looks of it, the main check is that the
two numbers (one positive, one negative) need to be xored together to return
0xc0c0c0c0. You can find many of these, but here's one example:

{% highlight raw %}
Enter first forecast parameter (integer): 1061109556
Enter second forecast parameter (integer): -12
0x55bde8294369
{% endhighlight %}

Now that we have ASLR destroyed, we're only missing the ability to someone gain
control of execution...

# Controlling Execution

We've looked at forecast already and found the leak. Maybe the execution is in
the test function? Let's try a simple stack overflow:

{% highlight raw %}
Choice: 2
Enter test data
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Received test data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Does it match (y/n)?
y
Program operating normally

*** stack smashing detected ***: <unknown> terminated
{% endhighlight %}

That stack smashing warning shows that we are indeed overwriting the stack
pointer (or at least the canary). Looking at the code, the following is
responsible for this overwrite:

{% highlight c %}
puts("Enter test data");
iVar1 = __isoc99_scanf(&%s,&bLocalBuf);
{% endhighlight %}

The data is being read in with a "%s" format string into a buffer on the stack.
This is actually something that can be easily caught dynamically or and even
statically in this case. This has the same effect as the notorious __gets__
function that you know not to use.

But wait, can't we use this to incrementally write one more byte at a time,
then have the "Received test data" echo it back to us, thus leaking the stack
canary? Unfortunately no. This format string will null terminate whatever we
give it, and so we won't be able to read the canary out.

Well we're part way there... We have an overwrite. But we have no way to leak
the canary.. At this point I stalled out for a bit trying to figure out how to
leak the canary.

# That Darn Alarm

Remember there was an alarm? It was easy to pass up because many pwn challenges
in CTFs have alarms. And usually that's simply to help the organizers not get
DoS'd due to hanging connections. However, when looking at the handler I
noticed something strange:

{% highlight c %}
void alarm_handler(void)

{
  puts("Hey, you are taking too long");
  puts("I\'m only going to warn you once...");
  signal(0xe,*DAT_00104078);
  alarm(*(uint *)(DAT_00104078 + 1));
  return;
}
{% endhighlight %}

It's not uncommon to post something about the alarm in the handler. However, it
_is_ uncommon to register a new handler dynamically and re-register your
alarm. So where is that new handler pointer sitting? Let's look at the cross
references to it:

{% highlight raw %}
                             DAT_00104078
XREF[6]:     alarm_handler:00101338(*), 
                                                                                          alarm_handler:0010133f(R), 
                                                                                          alarm_handler:00101352(*), 
                                                                                          alarm_handler:00101359(R), 
                                                                                          main:00101752(*), 
                                                                                          main:0010175d(W)  
        00104078                 undefined8 ??
{% endhighlight %}

Looks like that address is being written to in main. After renaming this
address, I can see what I glanced over in the main function:

{% highlight c %}
local_28 = (__sighandler_t)0x0;
local_20 = 5;
cMySelection = '\0';
setvbuf(stdout,(char *)0x0,2,0);
setvbuf(stderr,(char *)0x0,2,0);
new_alarm_handler_pointer = &local_28;
{% endhighlight %}

The new alarm handler pointer is getting the address of main's stack! That
means, since I have a stack overflow in the test function, I could continue to
write until I eventually overwrite the pointer storing the exception handler.

But wait, wouldn't the canary catch me? In this case the answer is actually no.
The canary is only checked at the function epilogue. Since there's a validation
prompt after my input and prior to returning from the function, the canary is
actually never checked.

One subtle gotcha in the overwrite of the pointer is that, normally you would
overwrite with all 8 bytes (a pointer in 64-bit is 8 bytes). However, in this
case we're reading the input with the "%s" format string. This format string
adds an extra null at the end of the input to ensure it's a properly null
terminated string. The good thing here is that in normal user-space 64-bit
addresses, the top two bytes will actually be nulls. This has to do with normal
memory layouts and saving the upper space for the kernel. The details are not
important, but the upshot is that you only have to write the first 6 bytes of
the address, and let the format string add your null at the end. If you don't
do this you will overwrite the timeout field, which in this case is sitting
right next to the pointer in memory.

# The Final Exploit

The final exploit looks like this:

1. Leak the address of the binary with the forecast function
1. Overwrite the signal handler with a stack overflow in the test function
1. Do NOT enter anything at the validation prompt.
1. Wait upwards of 30 seconds for the alarm handler to trigger, then 5 more
   seconds for the second alarm to cause the print flag function to trigger.
1. Enjoy your flag.

{% highlight raw %}
Found main binary at: 0x55be698a0000
[*] Switching to interactive mode

Received test data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��i�U
Does it match (y/n)?
Hey, you are taking too long
I'm only going to warn you once...
sun{Fl0rida_man_w1ll_get_a_FL4G!}
{% endhighlight %}

# Downloads
- [florida-forecaster](https://github.com/NoTeamName/CTF2020/blob/master/SunshineCTF/pwn/florida-forecaster/florida_forecaster?raw=true)
- [win.py](https://github.com/NoTeamName/CTF2020/blob/master/SunshineCTF/pwn/florida-forecaster/win.py)

[AndroidStudio]: https://developer.android.com/studio
[angr]: http://angr.io/
[ASLR]: https://en.wikipedia.org/wiki/Address_space_layout_randomization
[bash]: https://www.gnu.org/software/bash/
[checksec]: https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec
[d2j]: https://github.com/pxb1988/dex2jar
[fork]: http://man7.org/linux/man-pages/man2/fork.2.html
[formatStringExploiter]: https://formatstringexploiter.readthedocs.io/en/latest/
[ghidra]: https://ghidra-sse.erg/
[jdgui]: http://java-decompiler.github.io/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[malloc]: http://man7.org/linux/man-pages/man3/malloc.3.html
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[pwntools]: http://docs.pwntools.com/en/stable/
[radare2]: https://rada.re/n/
[revenge]: https://revenge.readthedocs.io/en/latest/
[strings]: http://man7.org/linux/man-pages/man1/strings.1.html
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
