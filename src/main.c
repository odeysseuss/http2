#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int tcpListen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 10)) {
        perror("listen");
        return -1;
    }

    return fd;
}

int main(void) {
    int fd = tcpListen(8000);
    if (fd == -1) {
        return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    char buf[1024];

    while (1) {
        int client_fd = accept(fd, (struct sockaddr *)&client_addr, &len);
        if (client_fd == -1) {
            perror("accept");
            return -1;
        }

        printf("Connected to ==> %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        while (1) {
            ssize_t bytes_read = read(client_fd, &buf, 1024 - 1);
            if (bytes_read <= 0) {
                break;
            }
            buf[bytes_read] = '\0';
            write(client_fd, buf, bytes_read);
        }

        close(client_fd);
    }

    close(fd);

    return 0;
}
