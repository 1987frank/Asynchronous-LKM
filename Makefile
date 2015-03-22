TARGET = xjob

obj-m += $(TARGET).o

$(TARGET)-objs := sys_xjob.o producer.o consumer.o crc32.o algorithm.o

all: xhw3 xjob

xhw3: xhw3.c
	gcc -Wall -Werror xhw3.c -lpthread -o xhw3 #-I/lib/modules/$(shell uname -r)/build/arch/x86/include xhw3.c -o xhw3

xjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3
