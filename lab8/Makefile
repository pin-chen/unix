
CC		= gcc
CFLAGS	= -static-pie
PROGS	= runner

all: $(PROGS)

runner:lab8.c
	$(CC) -o $@ $^ $(CFLAGS)

test1:
	./runner ./sample1

test2:
	./runner ./sample2

test3:
	./runner ./sample3

cleanup:
	rm -f *.o

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__

