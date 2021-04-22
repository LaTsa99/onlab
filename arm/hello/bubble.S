.global bubble
.type bubble, @function

//x0: array pointer
//w1: length
bubble:
	sub sp, sp, #12		// increasing stack
	str x0, [sp]		// saving input 1 to stack
	str w1, [sp, 8]		// saving input 2 to stack
	sub w1, w1, #1		// setting max i = length - 1
	mov w0, wzr			// i = 0
outerloop:
	cmp w0, w1 			// if i == length -1
	b.eq end			// end of algorithm
	mov w2, wzr			// j = 0
	sub w3, w1, w0		// until j < length - i - 1
	ldr x4, [sp]		// move input array to x4
innerloop:
	cmp w2, w3			// j < length - i - 1
	b.eq outerend		// j==length-i-1 -> end inner loop
	ldr w5, [x4]		// j-th element of array
	ldr w6, [x4, #4]	// j+1-th element og array
	cmp w5, w6			// compare arr[j] and arr[j+1]
	b.le innerend		// if arr[j] < arr[j+1] no swap
	str w5, [x4, #4]	// swapping
	str w6, [x4]
innerend:
	add w2, w2, #1		// j += 1
	add x4, x4, #4		// moving array iterator to next integer
	b innerloop
outerend:
	add w0, w0, #1 		// i += 1
	b outerloop
end:
	ldr x0, [sp]		// returning the sorted array in x0
	add sp, sp, #12 	// decreasing stack
	ret