#include <stdio.h>
#include <unistd.h>


typedef int (*printf_ptr_t)(const char *format, ...);
int i = 0;

void solver(printf_ptr_t fptr) {
	char msg[100] = "Hello!";
#if 0
	for(int i = 0x150; i >= 0x0; i -= 0x4){
		if(i == 0x40){
			fptr("guess rsp: ");
		}else if(i == 0x50){
			fptr("buf: ");
		}else if (i == 0x68){
			fptr("guess canary: ");
		}else if (i == 0x70){
			fptr("guess rbp: ");
		}else if (i == 0x78){
			fptr("return address: ");
		}else if (i == 0x80){
			fptr("main rsp: ");
		}else if (i == 0x8c){
			fptr("magic: ");
		}else if (i == 0xf0){
			fptr("main rbp: ");
		}
		fptr("%p : 0x%08llx\n", msg + i, *(unsigned int*) (msg + i));
		/*for(int j = 0x7; j >= 0x0; j -= 0x1){
			fptr("%02x ", *(int*)(msg+i+j));
		}
		fptr("\n");*/
	}
#endif
//48 0
	fptr("%016llx\n", *(unsigned long long*) (msg + 0x68));
	fptr("%016llx\n", *(unsigned long long*) (msg + 0x70));
	fptr("%016llx\n", *(unsigned long long*) (msg + 0x78));
//48 0
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}