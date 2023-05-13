#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main() {
    int shmid;
    key_t key = 0x1337; // A key used for identifying the shared memory segment
    size_t size = 1024; // The size of the shared memory segment in bytes
    char *shared_memory;

    // Create a shared memory segment
    shmid = shmget(key, size, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    // Attach to the shared memory segment
    shared_memory = (char *) shmat(shmid, NULL, 0);
    if (shared_memory == (char *) -1) {
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    // Write to the shared memory segment
    sprintf(shared_memory, "Hello, world!");

    while(1) sleep(100);
    // Detach from the shared memory segment
    shmdt(shared_memory);

    return 0;
}
