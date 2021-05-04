obj-m += vapa.o

all:
	make -C $(HOME)/kernel_debug/linux M=$(PWD) modules

clean:
	make -C $(HOME)/kernel_debug/linux M=$(PWD) clean
