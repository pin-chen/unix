CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: hw1.o
	$(CC) -o $@ -shared $^

flush:
	rm -f *.log index.*

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__