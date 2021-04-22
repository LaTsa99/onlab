.global merge
.type merge, @function

// x0: array1 pointer
// w1: array1 length
// x2: array2 pointer
// w3: array2 length
merge:
	sub sp, sp, #48		// increase stack
	str x0, [sp]		// saving array1 to stack
	str w1, [sp, #8]	// saving length1 to stack
	str x2, [sp, #12]	// saving array2 to stack
	str w3, [sp, #20]	// saving length2 to stack
	str x29, [sp, #32]	// saving x29 and x30 for returning to caller
	str x30, [sp, #40]	// because calling malloc will modify these
	mov x0, xzr			// x0 to 0
	add w0, w1, w3		// length1 + length2
	lsl w0, w0, #2		// * 4
	bl malloc			// malloc new array on heap
	str x0, [sp, #24]	// saving the allocated address on stack
	ldr w1, [sp, #8]	// maxi from stack
	ldr w3, [sp, #20]	// maxj from stack
	mov w0, wzr			// i = 0
	mov w2, wzr			// j = 0
	ldr x4, [sp, #24]	// merged array to x4
	ldr x5, [sp]		// array1 to x5
	ldr x6, [sp, #12]	// array2 to x6
loop:
	cmp w0, w1 			// i < maxi 
	b.eq restsecond		// if no, then second array left
	cmp w2, w3			// j < maxj
	b.eq restfirst		// if no, then first array left
	ldr w9, [x5]		// getting array1[i]
	ldr w10, [x6]		// getting array2[j]
	cmp w9, w10			// compare array1[i], array2[j]
	b.lt addfirst		// array[i] < array2[j]
	b.gt addsecond		// array[i] > array2[j]
	b.eq addboth		// array[i] == array2[j]
addfirst:
	str w9, [x4]		// adding array1[i] to new array
	add w0, w0, #1		// i+=1
	add x4, x4, #4		// increase new array iterator
	add x5, x5, #4		// increase array1 iterator
	b loop
addsecond:
	str w10, [x4]		// adding array2[j] to new array
	add w2, w2, #1		// j+= 1
	add x4, x4, #4		// increase new array iterator
	add x6, x6, #4		// increase array2 iterator
	b loop
addboth:
	str w9, [x4]		// adding array1[i] to new array
	str w10, [x4, #4]!	// adding array2[j] to new array and increase new array iterator
	add w0, w0, #1		// i+=1
	add w2, w2, #1		// j+=1
	add x4, x4, #4		// increase new array iterator
	add x5, x5, #4		// increase array1 iterator
	add x6, x6, #4		// increase array2 iterator
	b loop
restfirst:
	cmp w0, w10			// i < maxi
	b.eq mergeend
	ldr w9, [x5]		// getting array1[i]
	str w9, [x4]		// adding array1[i] to new array
	add w0, w0, #1 		// i+=1
	add x4, x4, #4		// increase new array iterator
	add x5, x5, #4		// increase array1 iterator
	b restfirst
restsecond:
	cmp w2, w3			// j < maxj
	b.eq mergeend
	ldr w10, [x6]		// getting array2[j]
	str w10, [x4]		// adding array2[j] to new array
	add w2, w2, #1		// j+=1
	add x4, x4, #4		// increase new array iterator
	add x6, x6, #4		// increase array2 iterator
	b restsecond
mergeend:
	ldr x0, [sp, #24]	// return new array in x0
	ldr x29, [sp, #32]	// reset x29
	ldr x30, [sp, #40]	// reset x30
	add sp, sp, #48		// decreasing stack
	ret