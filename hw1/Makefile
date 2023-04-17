CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: hw1.o
	$(CC) -o $@ -shared $^

test1:
	./launcher ./sandbox.so config.txt cat /etc/passwd
test2:
	./launcher ./sandbox.so config.txt cat /etc/hosts
test3:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem
test4:
	echo 'Deleted because duplicated to Example1.'
test5:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1
test6:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1
test7:
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1
test8:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'

flush:
	rm -f *.log index.*

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__