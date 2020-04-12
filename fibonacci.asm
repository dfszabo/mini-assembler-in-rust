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