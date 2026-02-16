#define TCP_IMPLEMENTATION
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "tcp.h"

void readAndWrite(Conn *conn) {
    char buf[1024];

    while (1) {
        ssize_t bytes_recv = recv(conn->fd, &buf, 1024, 0);
        if (bytes_recv <= 0) {
            break;
        }

        int fd = sendall(conn->fd, buf, bytes_recv);
        if (fd == -1) {
            break;
        }
    }
}

int main(void) {
    char str[INET_ADDRSTRLEN];

    Listener *listener = tcpListen(8000);
    if (!listener) {
        return -1;
    }

    fprintf(stdout,
            "[Listening] %s:%d\n",
            inet_ntop(AF_INET, &listener->addr.sin_addr, str, INET_ADDRSTRLEN),
            ntohs(listener->addr.sin_port));

    while (1) {
        Conn *conn = tcpAccept(listener);
        if (!conn) {
            return -1;
        }

        fprintf(stdout,
                "[Connected] %s:%d\n",
                inet_ntop(AF_INET, &conn->addr.sin_addr, str, INET_ADDRSTRLEN),
                ntohs(conn->addr.sin_port));

        tcpHandler(conn, readAndWrite);
        tcpConnClose(conn);
    }
    tcpListenerClose(listener);

    return 0;
}
