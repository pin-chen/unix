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

#define errquit(m)	{ perror(m); _exit(-1); }
#define DEBUG 0

struct node{
    struct node *next;
    char data[100];
};

struct node_net{
    struct node_net *next;
    char ip[INET_ADDRSTRLEN];
    int port;
};

struct node_fd{
    struct node_fd *next;
    int fd;
    int filter;
};

struct node *open_blacklist = NULL, 
            *read_blacklist = NULL, 
            *getaddrinfo_blacklist = NULL;

struct node_net *connect_blacklist = NULL;
struct node_fd *fd_list = NULL;

static int logger_fd = 1;

void logger_setup(){
    char *env = getenv("LOGGER_FD");
    sscanf(env, "%d", &logger_fd);
}

void resolve(const char *name, int port){
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ALL;

    if(getaddrinfo(name, NULL, &hints, &result) != 0) errquit("getaddrinfo");

    for (struct addrinfo *p = result; p != NULL; p = p->ai_next) {
        struct node_net *tmp = connect_blacklist;
        connect_blacklist = malloc(sizeof(struct node_net));
        connect_blacklist->next = tmp;
        connect_blacklist->port = port;
        char *ip = connect_blacklist->ip;

        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
    }

    freeaddrinfo(result);
}

static int max_len;

void read_config(){
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t s;
    fp = fopen(getenv("SANDBOX_CONFIG"), "r");
    if(fp == NULL) errquit("fopen");
    int type = 0;
    while((s = getline(&line, &len, fp)) != -1){
        if(line[s-1] == '\n') line[s - 1] = '\0';
        if(line[s-2] == '\r') line[s - 2] = '\0';
        if(strcmp(line, "BEGIN open-blacklist") == 0){
            type = 1;
        }else if(strcmp(line, "END open-blacklist") == 0){
            type = 0;
        }else if(strcmp(line, "BEGIN read-blacklist") == 0){
            type = 2;
        }else if(strcmp(line, "END read-blacklist") == 0){
            type = 0;
        }else if(strcmp(line, "BEGIN connect-blacklist") == 0){
            type = 3;
        }else if(strcmp(line, "END connect-blacklist") == 0){
            type = 0;
        }else if(strcmp(line, "BEGIN getaddrinfo-blacklist") == 0){
            type = 4;
        }else if(strcmp(line, "END getaddrinfo-blacklist") == 0){
            type = 0;
        }else if(type == 1){
            struct node *tmp = open_blacklist;
            struct node *new_node = malloc(sizeof(struct node));
            open_blacklist = new_node;
            open_blacklist->next = tmp;
            for(int i = 0; i < s; i++){
                open_blacklist->data[i] = line[i];
            }
        }else if(type == 2){
            struct node *tmp = read_blacklist;
            read_blacklist = malloc(sizeof(struct node));
            read_blacklist->next = tmp;
            for(int i = 0; i < s; i++){
                if(line[i] == '\0'){
                    max_len = i;
                    break;
                }
                read_blacklist->data[i] = line[i];
            }
        }else if(type == 3){
            int port = 0;
            bool isport = false;
            for(int i = 0; i < s; i++){
                if(line[i] == '\0'){
                    break;
                }else if(line[i] == ':'){
                    line[i] = '\0';
                    isport = true;
                }else if(isport){
                    port = port * 10 + line[i] - '0';
                }
            }
            resolve(line, port);
        }else if(type == 4){
            struct node *tmp = getaddrinfo_blacklist;
            getaddrinfo_blacklist = malloc(sizeof(struct node));
            getaddrinfo_blacklist->next = tmp;
            for(int i = 0; i < s; i++){
                getaddrinfo_blacklist->data[i] = line[i];
            }
        }
    }
    fclose(fp);
    if(line) free(line);
}

bool is_same_file(const char *path1, const char *path2) {
    struct stat s1, s2;
    if(stat(path1, &s1) != 0) errquit("stat");
    if(stat(path2, &s2) != 0) errquit("stat");
    return s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino;
}

int my_open(const char *pathname, int flags, mode_t mode){
    for(struct node* ptr = open_blacklist; ptr != NULL; ptr = ptr->next){
        if(is_same_file(pathname, ptr->data)){
             dprintf(logger_fd, "[logger] open(\"%s, %d, %u\") = %d\n", pathname, flags, mode & S_IRUSR, -1);
            errno = EACCES;
            return -1;
        }
    }
    int rvalue = open(pathname, flags, mode);
     dprintf(logger_fd, "[logger] open(\"%s, %d, %u\") = %d\n", pathname, flags,  mode & S_IRUSR, rvalue);
    return rvalue;
}

ssize_t my_read(int fd, char *buf, size_t count){
    ssize_t rvalue = read(fd, buf, count);
    bool isexists = false;
    for(struct node_fd *ptr = fd_list; ptr != NULL; ptr = ptr->next){
        if(ptr->fd == fd){
            for(int i = 0; i < rvalue; i++){
                if(buf[i] == read_blacklist->data[ptr->filter]){
                    ptr->filter++;
                    if(ptr->filter == max_len){
                         dprintf(logger_fd, "[logger] read(%d, %p, %zu) = %d\n", fd, buf, count, -1);
                        close(fd);
                        errno = EIO;
                        return -1;
                    }
                }else{
                    ptr->filter = 0;
                }
            }
            isexists = true;
            break;
        }
    }
    char pathname[100];
    sprintf(pathname, "%d-%d-read.log", getpid(), fd);
    if(isexists){
        int tfd = open(pathname,  O_RDWR | O_APPEND, 0644);
        write(tfd, buf, rvalue);
        close(tfd);
    }else{
        struct node_fd *tmp = fd_list;
        fd_list = malloc(sizeof(struct node_fd));
        fd_list->next = tmp;
        fd_list->fd = fd;
        fd_list->filter = 0;
        for(int i = 0; i < rvalue; i++){
            if(buf[i] == read_blacklist->data[fd_list->filter]){
                fd_list->filter++;
                if(fd_list->filter == max_len){
                     dprintf(logger_fd, "[logger] read(%d, %p, %zu) = %d\n", fd, buf, count, -1);
                    close(fd);
                    errno = EIO;
                    return -1;
                }
            }else{
                fd_list->filter = 0;
            }
        }
        int tfd = open(pathname,  O_RDWR | O_CREAT | O_TRUNC, 0644);
        write(tfd, buf, rvalue);
        close(tfd);
        //
        sprintf(pathname, "%d-%d-write.log", getpid(), fd);
        tfd = open(pathname,  O_RDWR | O_CREAT | O_TRUNC, 0644);
        close(tfd);
        //
    }
     dprintf(logger_fd, "[logger] read(%d, %p, %zu) = %zd\n", fd, buf, count, rvalue);
    return rvalue;
}

ssize_t my_write(int fd, const void *buf, size_t count){
    bool isexists = false;
    for(struct node_fd *ptr = fd_list; ptr != NULL; ptr = ptr->next){
        if(ptr->fd == fd){
            isexists = true;
            break;
        }
    }
    char pathname[100];
    sprintf(pathname, "%d-%d-write.log", getpid(), fd);
    if(isexists){
        int tfd = open(pathname,  O_RDWR | O_APPEND, 0644);
        write(tfd, buf, count);
        close(tfd);
    }else{
        struct node_fd *tmp = fd_list;
        fd_list = malloc(sizeof(struct node_fd));
        fd_list->next = tmp;
        fd_list->fd = fd;
        int tfd = open(pathname,  O_RDWR | O_CREAT | O_TRUNC, 0644);
        write(tfd, buf, count);
        close(tfd);
        //
        sprintf(pathname, "%d-%d-read.log", getpid(), fd);
        tfd = open(pathname,  O_RDWR | O_CREAT | O_TRUNC, 0644);
        close(tfd);
        //
    }

    ssize_t rvalue = write(fd, buf, count);
    dprintf(logger_fd, "[logger] write(%d, %p, %zu) = %zd\n", fd, buf, count, rvalue);
    return rvalue;
}

void get_address(const struct sockaddr *address, char *ip, int *port){
    if(address->sa_family == AF_INET){
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
        *port = ntohs(ipv4->sin_port);
    }else if(address->sa_family == AF_INET6){
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET_ADDRSTRLEN);
        *port = ntohs(ipv6->sin6_port);
    }else{
        printf("Unknown address family\n");
        return;
    }
}


int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char ip[INET_ADDRSTRLEN];
    int port;
    get_address(addr, ip, &port);

    for(struct node_net* ptr = connect_blacklist; ptr != NULL; ptr = ptr->next){
        if(strcmp(ip, ptr->ip) == 0 && port == ptr->port){
            dprintf(logger_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, -1);
            errno = ECONNREFUSED;
            return -1;
        }
    }

    int rvalue = connect(sockfd, addr, addrlen);
    dprintf(logger_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, rvalue);
    return rvalue;
}

int my_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
    for(struct node* ptr = getaddrinfo_blacklist; ptr != NULL; ptr = ptr->next){
        if(strcmp(node, ptr->data) == 0){
            dprintf(logger_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, res, EAI_NONAME);
            return EAI_NONAME;
        }
    }

    int rvalue = getaddrinfo(node, service, hints, res);
    dprintf(logger_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, res, rvalue);
    return rvalue;
}

int my_system(const char *command){
    dprintf(logger_fd, "[logger] system(\"%s\")\n", command);
    int rvalue = system(command);
    return rvalue;
}

int my_close(int fd){
    for(struct node_fd *ptr = fd_list; ptr != NULL; ptr = ptr->next){
        if(ptr->fd == fd){
            ptr->filter = 0;
        }
    }
    return close(fd);
}

void parse_elf(char *elf){
    char command[100];
    char *env = getenv("LD_PRELOAD");
    setenv("LD_PRELOAD", "", 1);
    sprintf(command, "./parser /proc/%d/exe > ./got.txt", getpid());
    if(system(command) == -1){
        perror("system");
    }
    setenv("LD_PRELOAD", env, 1);
}

long main_base = 0, got_min, got_max;

void get_main_base() {
	int fd, sz;
	long tmp;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		if(sscanf(line, "%lx-%lx ", &main_base, &tmp) != 2) errquit("get_base/main");
		if(main_base != 0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

void get_got_base(long distance) {
	int fd, sz;
	long tmp1, tmp2;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		if(sscanf(line, "%lx-%lx ", &tmp1, &tmp2) != 2) errquit("get_base/main");
		if(tmp1 < main_base + distance && tmp2 > main_base + distance){
			got_min = tmp1;
			got_max = tmp2;
			return;
		}
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

void write_got(char *command, long offset){
    static bool ismprotect = false;
    if(!ismprotect){
        get_got_base(offset);
#if DEBUG
        printf("got_min: %lx\n", got_min);
        printf("got_max: %lx\n", got_max);
#endif
        if(mprotect((void *) got_min, (size_t)(got_max - got_min), PROT_READ | PROT_WRITE) != 0) errquit("mprotect");
        ismprotect = true;
    }
    void **got_table = (void**) (main_base + offset);
    if(strcmp(command, "open") == 0){
        *got_table = my_open;
    }else if(strcmp(command, "read") == 0){
        *got_table = my_read;
    }else if(strcmp(command, "write") == 0){
        *got_table = my_write;
    }else if(strcmp(command, "connect") == 0){
        *got_table = my_connect;
    }else if(strcmp(command, "getaddrinfo") == 0){
        *got_table = my_getaddrinfo;
    }else if(strcmp(command, "system") == 0){
        *got_table = my_system;
    }else if(strcmp(command, "close") == 0){
        *got_table = my_close;
    }
}

void read_got(){
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t s;
    fp = fopen("./got.txt", "r");
    if(fp == NULL) errquit("fopen");
    while((s = getline(&line, &len, fp)) != -1){
        char command[20] = {};
        int space = 0, x = 0;
        long offset = 0;
        for(int i = 0; i < s; i++){
            if(line[i] == '\n'){
                break;
            }else if(line[i] == ' '){
                command[x] = '\0';
                x = 0;
                space++;
            }else if(space == 0){
                command[x++] = line[i];
            }else if(space == 1){
                offset = offset * 10 + line[i] - '0';
            }
        }
#if DEBUG
        printf("%s %ld\n", command, offset);
#endif
        write_got(command, offset);
    }
    fclose(fp);
    if(line) free(line);
}

static int (*main_orig)(int, char **, char **);

int main_hook(int argc, char **argv, char **envp){
    read_config();
    logger_setup();
    parse_elf(argv[0]);
    get_main_base();
#if DEBUG
    printf("main base: %lx\n", main_base);
#endif
    read_got();
#if DEBUG
    printf("arg:\n");
    for (int i = 0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    puts("--- Before main ---");
#endif
    int rvalue = main_orig(argc, argv, envp);
#if DEBUG
    puts("--- After main ----");
    printf("[logger] main(%d, %p, %p) = %d\n", argc, argv, envp, rvalue);
#endif
    return rvalue;
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end){
    main_orig = main;
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}