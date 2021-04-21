.global merge
.type merge, @function

// x0: array1 pointer
// w1: array1 length
// x2: array2 pointer
// w3: array2 length
merge:
	sub sp, sp, #48
	str x0, [sp]
	str w1, [sp, #8]
	str x2, [sp, #12]
	str w3, [sp, #20]
	str x29, [sp, #32]
	str x30, [sp, #40]
	mov x0, xzr
	add w0, w1, w3		// length1 + length2
	lsl w0, w0, #2		// * 4
	bl malloc
	str x0, [sp, #24]
	ldr w1, [sp, #8]
	ldr w3, [sp, #20]
	mov w0, wzr			// i = 0
	mov w2, wzr			// j = 0
	ldr x4, [sp, #24]	// merged
	ldr x5, [sp]		// array1
	ldr x6, [sp, #12]	// array2
	//sub w1, w1, #1		// i < length1
	//sub w3, w3, #1		// j < length2
loop:
	cmp w0, w1
	b.eq restsecond
	cmp w2, w3
	b.eq restfirst
	ldr w9, [x5]
	ldr w10, [x6]
	cmp w9, w10
	b.lt addfirst
	b.gt addsecond
	b.eq addboth
addfirst:
	str w9, [x4]
	add w0, w0, #1
	add x4, x4, #4
	add x5, x5, #4
	b loop
addsecond:
	str w10, [x4]
	add w2, w2, #1
	add x4, x4, #4
	add x6, x6, #4
	b loop
addboth:
	str w9, [x4]
	str w10, [x4, #4]!
	add w0, w0, #1
	add w2, w2, #1
	add x4, x4, #4
	add x5, x5, #4
	add x6, x6, #4
	b loop
restfirst:
	cmp w0, w1
	b.eq mergeend
	ldr w9, [x5]
	str w9, [x4]
	add w0, w0, #1
	add x4, x4, #4
	add x5, x5, #4
	b restfirst
restsecond:
	cmp w2, w3
	b.eq mergeend
	ldr w10, [x6]
	str w10, [x4]
	add w2, w2, #1
	add x4, x4, #4
	add x6, x6, #4
	b restsecond
mergeend:
	ldr x0, [sp, #24]
	ldr x29, [sp, #32]
	ldr x30, [sp, #40]
	add sp, sp, #32
	ret