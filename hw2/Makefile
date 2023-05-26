
CC		= gcc
CFLAGS	= -lcapstone -D_GNU_SOURCE
PROGS	= sdb

all: $(PROGS)

sdb:hw2.c
	$(CC) -o $@ $^ $(CFLAGS)

test1:
	./runner ./hello64

test2:
	./runner ./hello

test3:
	./runner ./guess

cleanup:
	rm -f *.o

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__

