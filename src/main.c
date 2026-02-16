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
        ssize_t bytes_read = read(conn->fd, &buf, 1024 - 1);
        if (bytes_read <= 0) {
            break;
        }
        buf[bytes_read] = '\0';
        write(conn->fd, buf, bytes_read);
    }
}

int main(void) {
    Listener *listener = tcpListen(8000);
    if (!listener) {
        return -1;
    }

    while (1) {
        Conn *conn = tcpAccept(listener);
        if (!conn) {
            return -1;
        }
        printf("Connected to ==> %s\n", inet_ntoa(conn->addr.sin_addr));

        tcpHandler(conn, readAndWrite);
        tcpConnClose(conn);
    }
    tcpListenerClose(listener);

    return 0;
}
