.data
    res:
        .word 1
    div:
        .word 1
.text
    xor     %r2, %r2, %r2     # %r2 = 0
    movh    %r0, res          # %r0 = res & 0xffff0000
    addi    %r1, %r0, res     # %r1 = res
    addi    %r3, %r2, 1       # %r3 = 1
    stw     %r3, (%r1)        # res[0] = 1

    addi    %r4, %r2, 2       # %r4 = 1
    addi    %r0, %r2, 6       # %r0 = 6
loop:
    mul     %r3, %r3, %r4     # res *= r4
    addi    %r4, %r4, 1       # %r4++
    jne     %r4, %r0, loop    # if (%r4 != 6) goto loop
    stw     %r3, (%r1)        # res = r3 (5!)
    div     %r3, %r3, %r4     # r3 /= 6
    movh    %r0, div          # %r0 = div & 0xffff0000
    addi    %r1, %r0, div     # %r1 = div
    stw     %r3, (%r1)        # div = r3 (5! / 6)