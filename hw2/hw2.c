#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <capstone/capstone.h>
#define errquit(m) { perror(m); exit(-1); }
#define CC() { asm volatile ( "int3" );}
#define DEBUG 1
#define BUFFER_SIZE 0x1000
#define MAX_LEN 0x100
#define MAX_ARG 0x10
#define CODE_SIZE 10
#define NUM_ASM 5
// text setion begin & end addresss
uint64_t text_section_begin;
uint64_t text_section_end;
// struct of per breakpoint
typedef struct _breakpoint{
    struct _breakpoint *next;
    long code;
    uint64_t addr;
}breakpoint;
// linked list of breakpoint
breakpoint *breakpoint_list = NULL;
// previous is hit a breakpoint or not
int hit = 0;
// snapshot register
struct user_regs_struct anchor_regs;

int set_breakpoint(pid_t child_pid, uint64_t addr){
    // check is already set at that addr
    for(breakpoint *cur = breakpoint_list; cur != NULL; cur = cur->next){
        if(cur->addr == addr) return -1;
    }
    // get oringin code
    long code = ptrace(PTRACE_PEEKDATA, child_pid, addr, NULL);
    // store oringin code and addr
    breakpoint *tmp = breakpoint_list;
    breakpoint_list = malloc(sizeof(breakpoint));
    breakpoint_list->next = tmp;
    breakpoint_list->addr = addr;
    breakpoint_list->code = code;
    // wirte to int3
    long int3_code = (code & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKEDATA, child_pid, addr, int3_code);
    return 0;
}

void reset_breakpoint(pid_t child_pid, int step){
    if(step == 1){
        // reset all breakpoint to oringin code
        for(breakpoint *cur = breakpoint_list; cur != NULL; cur = cur->next){
            long code = ptrace(PTRACE_PEEKDATA, child_pid, cur->addr, NULL);
            code = (cur->code & 0xFF) | (code & ~0xFF);
            ptrace(PTRACE_POKEDATA, child_pid, cur->addr, code);
        }
    }else if(step == 2){
        // reset all breakpoint
        for(breakpoint *cur = breakpoint_list; cur != NULL; cur = cur->next){
            long code = ptrace(PTRACE_PEEKDATA, child_pid, cur->addr, NULL);
            code = (code & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKEDATA, child_pid, cur->addr, code);
        }
    }
}
/*
if(prev == NULL){
    breakpoint_list = cur->next;
    free(cur);
}else{
    prev->next = cur->next;
    free(cur);
}
*/
int is_breakpoint(pid_t child_pid, uint64_t addr){
    // check current addr is a breakpoint or not and print message
    breakpoint *prev = NULL;
    for(breakpoint *cur = breakpoint_list; cur != NULL; cur = cur->next){
        if(cur->addr == addr){
            ptrace(PTRACE_POKEDATA, child_pid, cur->addr, cur->code);
            printf("** hit a breakpoint at %p.\n", (void*)addr);
            hit = 1;
            return 1;
        }
        prev = cur;
    }
    hit = 0;
    return 0;
}

void store_memory(pid_t child_pid){
    char maps_file_path[MAX_LEN];
    // remove 
    if(access("./snapshot", F_OK) == 0 && system("rm -rf ./snapshot") < 0) errquit("system");
    // Create dir if does not exists
    if(mkdir("./snapshot", 0755) < 0) errquit("mkdir");
    sprintf(maps_file_path, "./snapshot/%d", child_pid);
    if(mkdir(maps_file_path, 0755) < 0) errquit("mkdir");
    // Read child proc maps
    sprintf(maps_file_path, "/proc/%d/maps", child_pid);
    FILE* maps_file = fopen(maps_file_path, "r");
    if(maps_file == NULL) errquit("fopen");
    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, maps_file) != NULL) {
        // Check memory can modified by child
        if(strstr(line, " rw-p ") == NULL && strstr(line, " rwxp ") == NULL) continue;
        // Load addr
        unsigned long start, end;
        sscanf(line, "%lx-%lx", &start, &end);
        // Calculate the size of the memory section
        unsigned long size = end - start;
        // Allocate buffer to store the memory contents
        char* buffer = (char*)malloc(size);
        if (buffer == NULL) errquit("malloc");
        // Read memory contents from child process
        struct iovec local_iov = { buffer, size };
        struct iovec remote_iov = { (void*)start, size };
        ssize_t bytesRead = process_vm_readv(child_pid, &local_iov, 1, &remote_iov, 1, 0);
        if (bytesRead == -1) errquit("process_vm_readv");
        // Save the memory contents to a file
        char snapshot_file_path[MAX_LEN];
        sprintf(snapshot_file_path, "./snapshot/%d/%lx-%lx.bin", child_pid, start, end);
        int snapshot_fd = open(snapshot_file_path, O_WRONLY | O_CREAT, 0644);
        if (snapshot_fd == -1) errquit("open");
        // Write
        ssize_t bytesWritten = write(snapshot_fd, buffer, size);
        if (bytesWritten == -1) errquit("write");
        // Close the file and free the buffer
        close(snapshot_fd);
        free(buffer);
    }
}

void load_memory(pid_t child_pid){
    // open dir
    char directory_path[MAX_LEN];
    sprintf(directory_path, "./snapshot/%d", child_pid);
    DIR* dir = opendir(directory_path);
    if(dir == NULL) errquit("opendir");
    // traverse files
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Check if the entry is a regular file
            // Construct the full path of the memory snapshot file
            char snapshot_file_path[BUFFER_SIZE];
            snprintf(snapshot_file_path, sizeof(snapshot_file_path), "%s/%s", directory_path, entry->d_name);
            // Get the starting address and size from the file name
            unsigned long start, end;
            sscanf(entry->d_name, "%lx-%lx.bin", &start, &end);
            unsigned long size = end - start;
            // Open the memory snapshot file
            int snapshot_fd = open(snapshot_file_path, O_RDONLY);
            if(snapshot_fd == -1) errquit("open");
            // Allocate buffer to read the memory contents
            char buffer[BUFFER_SIZE];
            // Write memory contents back to child process
            unsigned long remaining = size;
            unsigned long address = start;
            while (remaining > 0) {
                // Calculate the size to read in this iteration
                size_t readSize = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
                // Read memory contents from the snapshot file
                ssize_t bytesRead = read(snapshot_fd, buffer, readSize);
                if (bytesRead == -1) errquit("read");
                // Write memory contents to child process
                struct iovec local_iov = { buffer, bytesRead };
                struct iovec remote_iov = { (void*)address, bytesRead };
                ssize_t bytesWritten = process_vm_writev(child_pid, &local_iov, 1, &remote_iov, 1, 0);
                if (bytesWritten == -1) errquit("process_vm_writev");
                // Update remaining size and address
                remaining -= bytesWritten;
                address += bytesWritten;
            }
            // Close the memory snapshot file
            close(snapshot_fd);
        }
    }
    closedir(dir);
}

void disassemble(pid_t child_pid, uint64_t addr){
    csh handle;
    cs_insn *insn;
    int num = 0;
    size_t count = 0;
    long code[CODE_SIZE];
    // disassemble only with oringin code instead breakpoint
    reset_breakpoint(child_pid, 1);
    // init
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open");
    // find memory which can be disassembled with 5 or more instruction
    for(uint64_t offset = 0; count < NUM_ASM; offset += sizeof(long)){
        code[num] = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)(addr + offset), NULL);
        count = cs_disasm(handle, (const uint8_t*)&code, offset + sizeof(long), addr, 0, &insn);
        cs_free(insn, count);
        num++;
        if(num >= CODE_SIZE) errquit("CODE_SIZE");
    }
    // disasm and output with format
    count = cs_disasm(handle, (const uint8_t*)&code, sizeof(long) * num, addr, 0, &insn);
    for(size_t j = 0; j < NUM_ASM; j++){
        if(insn[j].address >= text_section_end){
            printf("** the address is out of the range of the text section.\n");
            break;
        }
        printf("%12lx:", insn[j].address);
        for (size_t i = 0; i < insn[j].size; i++) printf(" %02x", insn[j].bytes[i]);
        printf("%*s%s\t%s\n", (11 - insn[j].size) * 3, "", insn[j].mnemonic, insn[j].op_str);
    }
    // recovery
    cs_free(insn, count);
    cs_close(&handle);
    reset_breakpoint(child_pid, 2);
}

int _si(pid_t child_pid, int argc, char *argv[]){
    int status;
    struct user_regs_struct regs;
    // step always run oringin instruction, instead breakpoint
    reset_breakpoint(child_pid, 1);
    // single step
    if(ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) errquit("PTRACE_SINGLESTEP");
    if(waitpid(child_pid, &status, 0) < 0) errquit("waitpid");
    // if child terminate, exit, or error return
    if(WIFEXITED(status)){
        printf("** the target program terminated.\n");
        exit(0);
    }else if(!WIFSTOPPED(status)){
        return -1;
    }
    // set back breakpoint
    reset_breakpoint(child_pid, 2);
    hit = 0;
    // check is this stop because of breakpoint
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    if(is_breakpoint(child_pid, regs.rip));
    // disassemble
    disassemble(child_pid, regs.rip);
    return 0;
}

int _cont(pid_t child_pid, int argc, char *argv[]){
    int status;
    struct user_regs_struct regs;
    // if hit before, run oringin next intruction first
    if(hit){
        reset_breakpoint(child_pid, 1);
        if(ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) errquit("PTRACE_SINGLESTEP");
        if(waitpid(child_pid, &status, 0) < 0) errquit("waitpid");
        reset_breakpoint(child_pid, 2);
        hit = 0;
    }
    // cont
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    if(waitpid(child_pid, &status, 0) < 0) errquit("waitpid");
    // if child terminate, exit, or error return
    if(WIFEXITED(status)){
        printf("** the target program terminated.\n");
        exit(0);
    }else if(!WIFSTOPPED(status)){
        return -1;
    }
    // check is this stop because of breakpoint
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    if(is_breakpoint(child_pid, regs.rip - 0x1)){
        regs.rip -= 0x1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
    }
    // disassemble
    disassemble(child_pid, regs.rip);
}

int _break(pid_t child_pid, int argc, char *argv[]){
    // check argument correct or not
    if(argc < 2) return -1;
    uint64_t addr = strtoull(argv[1], NULL, 16);
    if(addr < text_section_begin || addr >= text_section_end) return -1;
    // set breakpoint
    if(set_breakpoint(child_pid, addr) < 0){
        printf("** Already set a breakpoint at %s.\n", argv[1]);
    }else{
        printf("** set a breakpoint at %s.\n", argv[1]);
    }
    return 0;
}

void _anchor(pid_t child_pid, int argc, char *argv[]){
    // store register to snapshot
    ptrace(PTRACE_GETREGS, child_pid, NULL, &anchor_regs);
    // store memory to snapshot
    store_memory(child_pid);
    printf("** dropped an anchor\n");
}

void _timetravel(pid_t child_pid, int argc, char *argv[]){
    hit = 1;
    // load register from snapshot
    ptrace(PTRACE_SETREGS, child_pid, NULL, &anchor_regs);
    // load memory from snapshot
    load_memory(child_pid);
    printf("** go back to the anchor point\n");
    disassemble(child_pid, anchor_regs.rip);
}

int update_text_section_end(const char* executable_path) {
    long text_section_size = 0;
    char readelf_cmd[MAX_LEN];
    // read elf header with no newline for per section info
    snprintf(readelf_cmd, sizeof(readelf_cmd), "readelf -W -S %s", executable_path);
    // run readelf get output of text section length
    FILE* readelf_fp = popen(readelf_cmd, "r");
    if (!readelf_fp) return -1;
    char line[MAX_LEN];
    while (fgets(line, sizeof(line), readelf_fp)) {
        if (strstr(line, ".text")) {
            strtok(line, ".text");
            strtok(NULL, " ");
            strtok(NULL, " ");
            strtok(NULL, " ");
            strtok(NULL, " ");
            char* size_field = strtok(NULL, " ");
            text_section_end = text_section_begin + strtoull(size_field, NULL, 16);
            break;
        }
    }
    // close
    pclose(readelf_fp);
    return 0;
}

int trace(pid_t child_pid, int argc, char *argv[]){
    int status, cmdc;
    char buffer[MAX_LEN];
    char *cmdv[MAX_ARG];
    // wait child stop
    if(waitpid(child_pid, &status, 0) < 0) errquit("waitpid");
    if(!WIFSTOPPED(status)) return -1;
    // if parent (tracer) termiate, kill child
    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_EXITKILL);
    // Welcome message
    printf("** program '");
    for(int i = 1; i < argc; i++){
        printf("%s", argv[i]);
        if(i != argc - 1) printf(" ");
    }
    printf("' loaded. entry point ");
    ptrace(PTRACE_GETREGS, child_pid, NULL, &anchor_regs);
    printf("%p\n", (void*) anchor_regs.rip);
    // Update text section info
    text_section_begin = anchor_regs.rip;
    update_text_section_end(argv[1]);
    // Disassemble
    disassemble(child_pid, anchor_regs.rip);
    //
    store_memory(child_pid);
    // Input command
    while(1){
        printf("(sdb) ");
        fgets(buffer, sizeof(buffer), stdin);
        buffer[strcspn(buffer, "\n")] = '\0';
        char* token = strtok(buffer, " ");
        cmdc = 0;
        while (token != NULL && cmdc < MAX_ARG) {
            cmdv[cmdc++] = token;
            token = strtok(NULL, " ");
        }
        if(cmdc <= 0) continue;
        if(strcmp(cmdv[0], "si") == 0){
            if(_si(child_pid, cmdc, cmdv) < 0) errquit("_si");
        }else if(strcmp(cmdv[0], "cont") == 0){
            if(_cont(child_pid, cmdc, cmdv) < 0) errquit("_cont");
        }else if(strcmp(cmdv[0], "break") == 0){
            if(_break(child_pid, cmdc, cmdv) < 0) printf("Usage: break <address>\n");
        }else if(strcmp(cmdv[0], "anchor") == 0){
            _anchor(child_pid, cmdc, cmdv);
        }else if(strcmp(cmdv[0], "timetravel") == 0){
            _timetravel(child_pid, cmdc, cmdv);
        }else if(strcmp(cmdv[0], "exit") == 0){
            break;
        }else{
            printf("Unkonw command: %s\n", cmdv[0]);
        }
    }
    return 0;
}

int main(int argc, char *argv[]){
    // check argument
    if(argc < 2){
        printf("Usage: ./sdb [program]\n");
        return 1;
    }
    // fork
    pid_t pid = fork();
    if(pid < 0) errquit("fork");
    if(pid == 0){
        // wait parenet trace and exec
        if(ptrace(PTRACE_TRACEME, NULL, NULL, NULL) < 0) errquit("PTRACE_TRACEME");
        if(execvp(argv[1], &argv[1]) < 0) errquit("execvp");
    }else{
        // trace child
        if(trace(pid, argc, argv) < 0) errquit("trace");
    }
    return 0;
}