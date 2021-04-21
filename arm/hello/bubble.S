.global bubble
.type bubble, @function

//x0: array pointer
//w1: length
bubble:
	sub sp, sp, #12
	str x0, [sp]
	str w1, [sp, 8]
	sub w1, w1, #1	// until i < length - 1
	mov w0, wzr		// i = 0
outerloop:
	cmp w0, w1 		// i < length -1
	b.eq end
	mov w2, wzr		// j = 0
	sub w3, w1, w0	// until j < length - i - 1
	ldr x4, [sp]
innerloop:
	cmp w2, w3		// j < length - i - 1
	b.eq outerend
	ldr w5, [x4]
	ldr w6, [x4, #4]
	cmp w5, w6		// compare arr[j] and arr[j+1]
	b.le innerend
	str w5, [x4, #4]// swapping
	str w6, [x4]
innerend:
	add w2, w2, #1	// j += 1
	add x4, x4, #4
	b innerloop
outerend:
	add w0, w0, #1 	// i += 1
	b outerloop
end:
	ldr x0, [sp]
	add sp, sp, #12
	ret