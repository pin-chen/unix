#include <stdio.h>
#include <unistd.h>


typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[100] = "%016llx\n";
	fptr(msg, *(unsigned long long*) (msg + 0x68));
	fptr(msg, *(unsigned long long*) (msg + 0x70));
	fptr(msg, *(unsigned long long*) (msg + 0x78));
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}