#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <elf.h>

#define errquit(m)	{ perror(m); _exit(-1); }
#define DEBUG 0

struct symbolInfo{
    struct symbolInfo *next;
    int index;
    int symbolNameOffset;
    int gotOffset;
};

struct symbolInfo *symbolList = NULL;

void parseELF(char *file){
    int fd;
    Elf64_Ehdr header;
    Elf64_Shdr *section_header_table;
    Elf64_Rela *rela_plt_header_table;
    Elf64_Sym *dynsym_header_table;
    char *section_header_string_table;
    char *dynstr_header_table;

    if((fd = open(file, O_RDONLY)) < 0) errquit("open");

    if(read(fd, &header, sizeof(header)) != sizeof(header)) errquit("read");

    section_header_table = malloc(sizeof(Elf64_Shdr) * header.e_shnum);
    if(section_header_table == NULL) errquit("malloc");

    if(lseek(fd, header.e_shoff, SEEK_SET) != header.e_shoff) errquit("lseek");

    if(read(fd, section_header_table, sizeof(Elf64_Shdr) * header.e_shnum) != sizeof(Elf64_Shdr) * header.e_shnum) errquit("read");

    section_header_string_table = malloc(section_header_table[header.e_shstrndx].sh_size);
    if(section_header_string_table == NULL) errquit("malloc");

    if(lseek(fd, section_header_table[header.e_shstrndx].sh_offset, SEEK_SET) != section_header_table[header.e_shstrndx].sh_offset) errquit("lseek");

    if(read(fd, section_header_string_table, section_header_table[header.e_shstrndx].sh_size) != section_header_table[header.e_shstrndx].sh_size) errquit("read");

    for(int i = 0; i < header.e_shnum; i++) {
        if(strcmp((char *) (section_header_string_table + section_header_table[i].sh_name), ".rela.plt") == 0){
#if DEBUG
            printf("Name: %s\n", (char *) (section_header_string_table + section_header_table[i].sh_name));
            printf("Offset: %lx\n", section_header_table[i].sh_offset);
#endif   
            long num = section_header_table[i].sh_size / section_header_table[i].sh_entsize;
#if DEBUG
            printf("Entries: %lu\n", num);
#endif 
            rela_plt_header_table = malloc(section_header_table[i].sh_size);
            if(rela_plt_header_table == NULL) errquit("malloc");

            if(lseek(fd, section_header_table[i].sh_offset, SEEK_SET) != section_header_table[i].sh_offset)  errquit("lseek");
            
            if(read(fd, rela_plt_header_table, section_header_table[i].sh_size) != section_header_table[i].sh_size)  errquit("read");
            
            for(int j = 0; j < num; j++){          
#if DEBUG
                printf("rela offset: %lx\n", rela_plt_header_table[j].r_offset);
                printf("rela info: %lx\n", rela_plt_header_table[j].r_info);
#endif       
                struct symbolInfo *tmp = symbolList;
                symbolList = malloc(sizeof(struct symbolInfo));
                symbolList->next = tmp;
                symbolList->index = rela_plt_header_table[j].r_info / 0x100000000;
                symbolList->gotOffset = rela_plt_header_table[j].r_offset;
            }
            break;
        }
    }
    for(int i = 0; i < header.e_shnum; i++){
        if(strcmp((char *) (section_header_string_table + section_header_table[i].sh_name), ".dynsym") == 0){
#if DEBUG
            printf("Name: %s\n", (char *) (section_header_string_table + section_header_table[i].sh_name));
            printf("Offset: %lx\n", section_header_table[i].sh_offset);
#endif   
            long num = section_header_table[i].sh_size / sizeof(Elf64_Sym);
#if DEBUG
            printf("Entries: %lu\n", num);
#endif 
            dynsym_header_table = malloc(section_header_table[i].sh_size);
            if(dynsym_header_table == NULL) errquit("malloc");

            if(lseek(fd, section_header_table[i].sh_offset, SEEK_SET) != section_header_table[i].sh_offset) errquit("lseek");
            
            if(read(fd, dynsym_header_table, section_header_table[i].sh_size) != section_header_table[i].sh_size) errquit("read");

            for(struct symbolInfo *ptr = symbolList; ptr != NULL; ptr = ptr->next){           
#if DEBUG
                printf("Symbol name offset: %x\n", dynsym_header_table[ptr->index].st_name);
#endif
                ptr->symbolNameOffset = dynsym_header_table[ptr->index].st_name;
            }

        }else if(strcmp((char *) (section_header_string_table + section_header_table[i].sh_name), ".dynstr") == 0){
#if DEBUG
            printf("Name: %s\n", (char *) (section_header_string_table + section_header_table[i].sh_name));
            printf("Offset: %lx\n", section_header_table[i].sh_offset);
#endif 
            dynstr_header_table = malloc(section_header_table[i].sh_size);
            if(dynstr_header_table == NULL) errquit("malloc");

            if(lseek(fd, section_header_table[i].sh_offset, SEEK_SET) != section_header_table[i].sh_offset) errquit("lseek");
            
            if(read(fd, dynstr_header_table, section_header_table[i].sh_size) != section_header_table[i].sh_size) errquit("read");

            for(struct symbolInfo *ptr = symbolList; ptr != NULL; ptr = ptr->next){
#if DEBUG        
                printf("Sybol name: %s\n", (char *)(dynstr_header_table + ptr->symbolNameOffset));
                printf("Got offset: %x\n", ptr->gotOffset);
#endif
                char *tmp = (char *)(dynstr_header_table + ptr->symbolNameOffset);
                if(strcmp(tmp, "open") == 0){
                }else if(strcmp(tmp, "read") == 0){
                }else if(strcmp(tmp, "write") == 0){
                }else if(strcmp(tmp, "connect") == 0){
                }else if(strcmp(tmp, "getaddrinfo") == 0){
                }else if(strcmp(tmp, "system") == 0){
                }else if(strcmp(tmp, "close") == 0){
                }else{
                    continue;
                }
                printf("%s %d\n", tmp, ptr->gotOffset);
            }
        }
    }

    free(dynstr_header_table);
    free(dynsym_header_table);
    free(rela_plt_header_table);
    free(section_header_string_table);
    free(section_header_table);
    close(fd);
}

int main(int argc, char **argv) {
    parseELF(argv[1]);
    return 0;
}