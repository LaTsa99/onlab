cmd_/home/latsa/kernel_debug/linux/src/hello/modules.order := {   echo /home/latsa/kernel_debug/linux/src/hello/hello.ko; :; } | awk '!x[$$0]++' - > /home/latsa/kernel_debug/linux/src/hello/modules.order
