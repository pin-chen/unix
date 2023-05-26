#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <string.h>

#define MEM_LEN 11

#define CC() { asm volatile ( "int3" );}
#define DEBUG 0
#define ROUND 2
int HINT = 1;
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program>\n", argv[0]);
        return 1;
    }
    char new_magic_value[] = "0000000000";
    int found = 0;

    for(int k = 0; k < 1 << 9; k++){
        fflush(stderr);
        fflush(stdout);
        //printf("%d\n",k);
        pid_t child_pid;
        int status;
        if(found == 1){
            printf("FOUND\n");
            fflush(stderr);
            fflush(stdout);
            exit(0);
        }

        int pipefd[2];
        if (pipe(pipefd) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }

        int pipefd2[2];
        if (pipe(pipefd2) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }

        for(int j = 0; j < 9; j++){
            if(1 << j & k){
                new_magic_value[j] = '1';
            }else{
                new_magic_value[j] = '0';
            }
        }
        
        child_pid = fork();
        HINT++;
        if(child_pid < 0){
            perror("fork");
            exit(1);
        }
        if (child_pid == 0) {
            //printf("HINT: %d\n", HINT);
            //fflush(stdout);
            if(found == 1) exit(1);
            //
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd2[0]);
            dup2(pipefd2[1], STDERR_FILENO);
            // Child process
            int e = execvp(argv[1], &argv[1]);
            exit(1);
        } else {
            close(pipefd[1]);
            close(pipefd2[1]);
            // Parent process
            ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
            waitpid(child_pid, &status, 0);

            if (WIFSTOPPED(status)) {
#if DEBUG
                printf("Child stopped\n");
#endif
                //struct user_regs_struct init_regs;
                //char process_memory[MEM_LEN];
                int i = 0;
                struct user_regs_struct regs;
                // Enter the tracing loop
                long magic_addr = 0;
                unsigned long addr = 0;
                char buffer[11];
                char magic1[11] = { 0 };
                while (1) {
#if DEBUG
                    printf("CONT\n");
#endif
                    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                    waitpid(child_pid, &status, 0);
                    if (WIFEXITED(status))
                        break;
                    if (WIFSTOPPED(status)) {
                        if(i == ROUND){
                            memset(magic1, '0', sizeof(magic1)-1);
                            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                            //printf("%llx\n", regs.rip);
                            //printf("%lx\n", sizeof(long));
                            while (1) {
                                if(addr > 0x100000) break;
                                long data = ptrace(PTRACE_PEEKDATA, child_pid, regs.rip + addr, NULL);
                                memcpy(buffer, &data, 8);
                                if (memcmp(buffer, magic1, 8) == 0) {
                                    magic_addr = regs.rip + addr;
#if DEBUG
                                    printf("addr: %lx\n", addr);
                                    printf("data: %lx\n", data);
                                    printf("buffer: %s\n", buffer);
                                    printf("--------------------\n");
#endif
                                    //break;
                                }
                                addr += sizeof(long);
                            }
                            if (magic_addr != 0) {
                                //printf("Found magic variable address: 0x%lx\n", magic_addr);
                                // Modify the value of the magic variable
                                ptrace(PTRACE_POKEDATA, child_pid, magic_addr, *(long*)new_magic_value);
                                ptrace(PTRACE_POKEDATA, child_pid, magic_addr + sizeof(long), *(long*)(new_magic_value + 8));
                            } else {
                                printf("Failed to find the magic variable address\n");
                            }
                        }
#if DEBUG
                        if(0 && i >= ROUND){
                            long data = ptrace(PTRACE_PEEKDATA, child_pid, magic_addr, NULL);
                            printf("addr: %lx\n", magic_addr);
                            printf("data: %lx\n", data);
                            memcpy(buffer, &data, 8);
                            printf("buffer: %s\n", buffer);
                        }
#endif 

                        if(i == 4){
                            char buffer[BUFSIZ];
                            ssize_t n;
                            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                            ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
                            while ((n = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
                                for(int w = 0; w < n; w++){
                                    if(buffer[w] == '!'){
                                        //printf("BINGO HINT: %d\n", HINT);
                                        //fflush(stdout);
                                        found = 1;
                                        break;
                                    }
                                }
                                if(strncmp(buffer, ".", 1) == 0){
                                    continue;
                                }
                                write(STDOUT_FILENO, buffer, n);
                            }
                            close(pipefd[0]);
                            close(pipefd2[0]);
                            waitpid(child_pid, &status, 0);
                            if(found == 1){
                                fflush(stdout);
                                exit(0);
                            }
                            break;
                        }
                    }
                    i++;
                }
            }
        }
    }

    return 0;
}
