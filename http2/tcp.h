#ifndef TCP_H
#define TCP_H

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int port;
    int fd;
} Listener;

typedef struct {
    struct sockaddr_in addr;
    socklen_t size;
    int fd;
} Conn;

Listener *tcpListen(int port);
Conn *tcpAccept(Listener *listener);
void tcpHandler(Conn *conn, void (*handler)(Conn *conn));
void tcpConnClose(Conn *conn);
void tcpListenerClose(Listener *listener);

#ifdef TCP_IMPLEMENTATION

Listener *tcpListen(int port) {
    Listener *listener = malloc(sizeof(Listener));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        goto clean;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        // goto clean;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        goto clean;
    }

    if (listen(fd, SOMAXCONN)) {
        perror("listen");
        goto clean;
    }

    listener->fd = fd;
    listener->port = port;

    return listener;

clean:
    free(listener);
    return NULL;
}

Conn *tcpAccept(Listener *listener) {
    Conn *conn = malloc(sizeof(Conn));

    conn->size = sizeof(struct sockaddr_in);
    conn->fd =
        accept(listener->fd, (struct sockaddr *)&conn->addr, &conn->size);

    if (conn->fd == -1) {
        perror("accept");
        free(conn);
        return NULL;
    }

    return conn;
}

void tcpHandler(Conn *conn, void (*handler)(Conn *conn)) {
    handler(conn);
}

void tcpConnClose(Conn *conn) {
    if (!conn) {
        return;
    }

    close(conn->fd);
    free(conn);
}

void tcpListenerClose(Listener *listener) {
    if (!listener) {
        return;
    }

    close(listener->fd);
    free(listener);
}

#endif

#ifdef __cplusplus
}
#endif

#endif
