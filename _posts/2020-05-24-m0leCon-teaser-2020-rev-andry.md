---
layout:     post
title:      m0leCon teaser 2020 - Andry
date:       2020-05-24
summary:    Solution to m0leCon teaser 2020 challenge "Andry"
categories: writeups
thumbnail:  M0leconCTF
tags:
 - m0lecon
 - 2020
 - writeup
 - reverse
 - ghidra
 - revenge
 - android
 - apk
---

I didn't end up attempting this challenge during the competition, but
afterwards decided to give it a look. It turns out to be a pretty fun android
reversing challenge that [revenge][revenge] is helpful in solving.

The solution involved reversing the given apk, identifying the first input
checks, brute-forcing the correct input, identifying the first decryption
routine, manually decrypting to find a second stage dex file, and finally
reversing that stage to identify how the final flag needed to be decrypted.

# Triage

The given file is an APK (android application file). To start with, spin up an
emulator and connect to it via [revenge][revenge]:

```python
from revenge import Process, common, types, devices

# This will find your local android device and configure things
android = devices.AndroidDevice(type='usb')

# Install the apk
android.install("./andry.apk")

# Launch it
andry = android.spawn('*andry*', gated=False, load_symbols=['*andry*'])
```

![Main Screen](https://github.com/NoTeamName/CTF2020/raw/master/m0leCon/teaser/rev/andry/andry_main.png)

When we try entering "password" as the password, the app crashes. Clearly
something is amiss.

# Main App Code

Time to dig into the code a little. The basics for looking at the code involve:

1. unzip andry.apk
1. Run [d2j][d2j] on any classes*.dex files you find
1. Run [jdgui][jdgui] on the corresponding output jar files

Looking at the MainActivity, we can find the handler for our password
validation:

```java
protected void onCreate(Bundle paramBundle)
{
  super.onCreate(paramBundle);
  setContentView(2131361820);
  ((Button)findViewById(2131165250)).setOnClickListener(new View.OnClickListener()
  {
    public void onClick(View paramAnonymousView)
    {
      if (MainActivity.this.check_password().booleanValue())
      {
        Toast.makeText(MainActivity.this.getApplicationContext(), "Yes!", 0).show();
        paramAnonymousView = ((EditText)MainActivity.this.findViewById(2131165268)).getText().toString();
        DynamicLoaderService.startActionLoad(MainActivity.this.getApplicationContext(), paramAnonymousView);
        return;
      }
      Toast.makeText(MainActivity.this.getApplicationContext(), "No...", 0).show();
    }
  });
}
```

So we should be expecting to see "Yes!" or "No...". It's first calling
`check_password`, so we should check there next.

```java
private Boolean check_password()
{
  Object localObject1 = ((EditText)findViewById(2131165268)).getText().toString();
  Object localObject2 = Integer.valueOf(0);
  ListIterator localListIterator = splitBySize((String)localObject1, 2).listIterator();
  while (localListIterator.hasNext())
  {
    int i = localListIterator.nextIndex();
    int j = Integer.parseInt((String)localListIterator.next(), 16);
    switch (Integer.valueOf(i).intValue() + 1)
    {
    default: 
      localObject1 = localObject2;
      break;
    case 32: 
      localObject1 = localObject2;
      if (c32(j) == 261) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    case 31: 
      localObject1 = localObject2;
      if (c31(j) == 2676) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    case 30: 
      localObject1 = localObject2;
      if (c30(j) == 11315) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    case 29: 
      localObject1 = localObject2;
      if (c29(j) == 207) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    case 28: 
      localObject1 = localObject2;
      if (c28(j) == 1056) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
<snip>
    case 2: 
      localObject1 = localObject2;
      if (c2(j) == 2259) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    case 1: 
      localObject1 = localObject2;
      if (c1(j) == 6326) {
        localObject1 = Integer.valueOf(((Integer)localObject2).intValue() + 1);
      }
      break;
    }
    localObject2 = localObject1;
  }
  if (((Integer)localObject2).intValue() == 32) {
    return Boolean.TRUE;
  }
  return Boolean.FALSE;
}
```

So we can see that it's breaking up our input into two character chunks,
converting them to an integer, then calling a function with the input and
checking if the output is the expected. If the total number of items that match
is 32, then we're good.

Those `c1` `c2` etc params are actually called from the shared library that
comes with this application. You can see it here:

```java
public native int c1(int paramInt);
public native int c10(int paramInt);
public native int c11(int paramInt);
public native int c12(int paramInt);
public native int c13(int paramInt);
```

Luckily for us, we don't actually have to reverse those. Instead, so long as
they are deterministic in what they return, we can simply call them over and
over until we find the correct output.

# Brute Force Stage 1

To test the ability to call those functions with [revenge][revenge], you can
simply do:

{% highlight python %}
main = andry.java.classes['com.andry.MainActivity']

# Need to have an actual instance to call
main = andry.java.find_active_instance(main)

main.c1(1)() 
# 646
{% endhighlight %}

What we just did there was to actually call the function directly with our
input. With this in mind, we can now brute force stage 1 to find the expected
input.

```python
# These were extracted from the java decompiled view
goals = [6326, 2259, 455, 1848, 275400, 745, 1714, 1076, 12645, 2120, 153664, 10371, 37453, 203640, 691092, 36288, 753, 2011, 59949, 18082, 538, 12420, 2529, 1130, 6076, 11702, 47217, 1056, 207, 11315, 2676, 261]

# Generically find the desired output for the given function
def find_solution(attr, eq):
    for i in range(256):
        if getattr(main, attr)(i)() == eq:
            return i

flag = ""

for i in range(1,33):
    print(flag)
    flag += "{:02x}".format(find_solution("c"+str(i), goals[i-1]))

assert flag == "48bb6e862e54f2a795ffc4e541caed4d0bf985de4d3d7c5df73cf960638b4bf2"
```

While we know that should be correct, when we input it, the program still
crashes... Need to take a look at the next section.

# Code Analysis 2

According to the decompilation, if we pass step one we should hit the call
`DynamicLoaderService.startActionLoad`. To verify this, let's quickly hook that
method so that [revenge][revenge] tells us if we hit it or not.

```python
# Grab the loader service class
dls = andry.java.classes['com.andry.DynamicLoaderService']

# This will send us a message "hit" if this method is called
dls.startActionLoad.implementation = "function (x) { send('hit'); return this.startActionLoad(x); }"

# Paste in the first part again and you see:
# on_message: [{'type': 'send', 'payload': 'hit'}, None]

# Revert your override with
dls.startActionLoad.implementation = None
```

So we can confirm this is getting hit. Here's some code for the function:

```java
public static void startActionLoad(Context paramContext, String paramString)
  {
    Intent localIntent = new Intent(paramContext, DynamicLoaderService.class);
    localIntent.setAction("com.andry.action.LOAD");
    localIntent.putExtra("com.andry.extra.password", paramString);
    paramContext.startService(localIntent);
  }
  
  protected void onHandleIntent(Intent paramIntent)
  {
    if ((paramIntent != null) && ("com.andry.action.LOAD".equals(paramIntent.getAction()))) {
      handleActionFoo(paramIntent.getStringExtra("com.andry.extra.password"));
    }
  }
```

Following it down to `handleActionFoo`:

{% highlight java %}
private String DynamicDecode(byte[] paramArrayOfByte, String paramString1, String paramString2)
{
  throw new UnsupportedOperationException("NOT IMPLEMENTED YET! PURE GUESSING!");
}

private void XORDecrypt(byte[] paramArrayOfByte, String paramString)
{
  throw new UnsupportedOperationException("NOT IMPLEMENTED YET! PURE GUESSING!");
}

private void handleActionFoo(String paramString)
{
  Object localObject = getApplicationContext().getAssets();
  try
  {
    localObject = IOUtils.toByteArray(((AssetManager)localObject).open("enc_payload"));
    XORDecrypt((byte[])localObject, paramString);
    paramString = DynamicDecode((byte[])localObject, "decrypt", "EASYPEASY");
    localObject = new StringBuilder();
    ((StringBuilder)localObject).append("ptm{");
    ((StringBuilder)localObject).append(paramString);
    ((StringBuilder)localObject).append("}");
    Log.i("FLAG: ", ((StringBuilder)localObject).toString());
    return;
  }
  catch (IOException paramString)
  {
    paramString.printStackTrace();
  }
}
{% endhighlight %}

So our program is crashing because there are two methods that are not
implemented yet and are throwing exceptions.

# Decrypting Payload 1

The application is grabbing some encrypted payload from a local resource. We
could use something like [AndroidStudio][AndroidStudio] to pull the encrypted
blob out directly. However, let's use [revenge][revenge] to pull it out
dynamically instead.

To do this, all we need to do is implement the `XORDecrypt` method that gets
called with the array.

```python
dls = andry.java.classes['com.andry.DynamicLoaderService']

# Simply echo back to us what that method was called with
dls.XORDecrypt.implementation = "function (x, y) { send([x,y]); }" 
```

The blob is the first argument and the key (which we gave it) is the second.
Since this is apparently a basic [xor chipher][xor cipher], we can just decrypt
it directly.

{% highlight python %}
from binascii import unhexlify
import numpy as np

key = unhexlify(x[1])

# Blob was returned as signed chars, need to standardize it to unsigned
blob = [np.uint8(np.int8(y)) for y in x[0]]

blob2 = []
for i, val in enumerate(blob):
    blob2.append(val ^ key[i%len(key)])

# We're being careful here with int to byte conversion since chr() can
# sometimes return unexpected results.
blob2 = b"".join(int.to_bytes(int(x), length=1, byteorder='little') for x in blob2)
# b'dex\n035\x00\xa3\x90\xd5VN\xa4\xb1^\'\xe...`
{% endhighlight %}

Our blob2 appears to be a dex file. The call after XORing this blob is to call
`decrypt` inside it. Time to open the new dex file up, same as the first ones.

# Code Analysis 3

Opening up the new dex file in [jdgui][jdgui], we can find the `decrypt` method
being referenced:

```java
public class Inner
{
  public static String decrypt(String paramString)
  {
    int j = 0;
    String str2 = "NUKRPFUFALOXYLJUDYRDJMXHMWQW".toUpperCase();
    String str1 = "";
    int i = 0;
    while (i < str2.length())
    {
      int k = str2.charAt(i);
      str1 = str1 + (char)((k - paramString.charAt(j) + 26) % 26 + 65);
      j = (j + 1) % paramString.length();
      i += 1;
    }
    return str1;
  }
  
  public static String encrypt(String paramString1, String paramString2)
  {
    int j = 0;
    String str = paramString1.toUpperCase();
    paramString1 = "";
    int i = 0;
    while (i < str.length())
    {
      int k = str.charAt(i);
      paramString1 = paramString1 + (char)((k - 65 + (paramString2.charAt(j) - 'A')) % 26 + 65);
      j = (j + 1) % paramString2.length();
      i += 1;
    }
    return paramString1;
  }
  
  public void keep() {}
}
```

# Decrypting Payload 2

Now it's simply a matter of re-writing the java decryption method in python:

```python
str2 = "NUKRPFUFALOXYLJUDYRDJMXHMWQW"
out = ""

for i, val in enumerate(str2):
    out += chr((ord(val) - ord("EASYPEASY"[i%9]) + 26)%26 + 65)

# JUSTABUNCHOFAWFULANDROIDMESS
# ptm{JUSTABUNCHOFAWFULANDROIDMESS}
```

# Downloads
- [andry.zip](https://github.com/NoTeamName/CTF2020/raw/master/m0leCon/teaser/rev/andry/andry.apk)

[AndroidStudio]: https://developer.android.com/studio
[angr]: http://angr.io/
[bash]: https://www.gnu.org/software/bash/
[checksec]: https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec
[d2j]: https://github.com/pxb1988/dex2jar
[fork]: http://man7.org/linux/man-pages/man2/fork.2.html
[formatStringExploiter]: https://formatstringexploiter.readthedocs.io/en/latest/
[ghidra]: https://ghidra-sre.org/
[jdgui]: http://java-decompiler.github.io/
[ltrace]: http://man7.org/linux/man-pages/man1/ltrace.1.html
[malloc]: http://man7.org/linux/man-pages/man3/malloc.3.html
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[pwntools]: http://docs.pwntools.com/en/stable/
[radare2]: https://rada.re/n/
[revenge]: https://revenge.readthedocs.io/en/latest/
[strings]: http://man7.org/linux/man-pages/man1/strings.1.html
[xor cipher]: https://en.wikipedia.org/wiki/XOR_cipher
