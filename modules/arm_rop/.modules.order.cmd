cmd_/home/latsa/kernel_debug/linux/src/arm_rop/modules.order := {   echo /home/latsa/kernel_debug/linux/src/arm_rop/arm.ko; :; } | awk '!x[$$0]++' - > /home/latsa/kernel_debug/linux/src/arm_rop/modules.order
