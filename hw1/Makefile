CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
LDFLAGS = -lunwind -lunwind-$(shell uname -m)
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: hw1.o
	$(CC) -o $@ -shared $^ $(LDFLAGS)

clean:
	rm -f $(PROGS) *.o *.log index.*
	rm -rf __pycache__