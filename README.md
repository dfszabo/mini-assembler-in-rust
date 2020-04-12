# Mini assembler and emulator in Rust

A learning project, which I made after reading up until chapter 12 of the Rust book.

An input of the program is a hypothetical 32 bit machine assembly language which is influenced by **TriCore**, **MIPS** and **ARM**.
The program generates the encoded instructions as a u32 array and emulate it. The output is the state of the registers and memory
after executing the program.

**Example program:** First 10 number of fibonacci sequence
```
.data
    fib:
        .word 10
.text
    xor     %r2, %r2, %r2     # %r2 = 0
    movh    %r0, fib          # %r0 = fib & 0xffff0000
    addi    %r1, %r0, fib     # %r1 = fib
    addi    %r3, %r2, 1       # %r3 = 1
    stw     %r3, (%r1)        # fib[0] = 1
    addi    %r1, %r1, 4       # fib++
    stw     %r3, (%r1)        # fib[1] = 1
    addi    %r1, %r1, 4       # fib++

    addi    %r4, %r2, 2       # %r4 = 2
    addi    %r0, %r2, 10      # %r0 = 10
loop:
    ldw     %r5, -4(%r1)      # %r5 = *(fib-1)
    ldw     %r6, -8(%r1)      # %r6 = *(fib-2)
    add     %r7, %r5, %r6     # %r7 = *(fib-1) + *(fib-2)
    stw     %r7, (%r1)        # fib[%r4] = %r7
    addi    %r1, %r1, 4       # fib++
    addi    %r4, %r4, 1       # %r4++
    jne     %r4, %r0, loop    # if (%r4 != 10) goto loop
```
Output
```
       ###############################
       # Program execution finished. #
       ###############################

              Register bank content

+----------+-----------+-----------+-----------+
0x0000000a  0x00000028  0x00000000  0x00000001	
0x0000000a  0x00000001  0x00000001  0x00000001	
0x00000000  0x00000000  0x00000000  0x00000000	
0x00000000  0x00000000  0x00000000  0x00000000	
+----------+-----------+-----------+-----------+

                Memory content

+----------+-----------+-----------+-----------+
0x00000001  0x00000001  0x00000002  0x00000003	
0x00000005  0x00000008  0x0000000d  0x00000015	
0x00000022  0x00000037  0x20002206  0x00000004	
0x10000001  0x30001201  0x00003105  0x10004101	
0x00003105  0x10004101  0x40002201  0x0000a201	
0xfffc5102  0xfff86102  0x70006500  0x00007105	
0x10004101  0x40001401  0x40014003  0x00000000	
0x00000000  0x00000000  0x00000000  0x00000000	
0x00000000  0x00000000  0x00000000  0x00000000	
0x00000000  0x00000000  0x00000000  0x00000000	
+----------+-----------+-----------+-----------+
```
In the memory content part the first 10 entry is the fibonacci numbers in hexa form.

# TODO
Improve it after reading the rest of the book.
