#!/bin/sh

insmod $1
mknod $2 c 511 0
chmod a+rw $2
