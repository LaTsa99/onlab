aarch64-linux-gnu-gcc -c bubble.S -o bubble.o
aarch64-linux-gnu-gcc -c merge.S -o merge.o
aarch64-linux-gnu-gcc -c hello.c -o hello.o
aarch64-linux-gnu-gcc hello.o bubble.o merge.o -static -o hello
