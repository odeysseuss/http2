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
    struct sockaddr_in addr;
    socklen_t size;
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

int sendall(int fd, char *buf, int len);

#ifdef TCP_IMPLEMENTATION

Listener *tcpListen(int port) {
    Listener *listener = malloc(sizeof(Listener));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        goto clean;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        goto clean;
    }

    listener->fd = fd;
    listener->size = sizeof(listener->addr);
    listener->addr.sin_family = AF_INET;
    listener->addr.sin_port = htons(port);
    listener->addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&listener->addr, listener->size) == -1) {
        perror("bind");
        goto clean;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        perror("listen");
        goto clean;
    }

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
    if (!conn) {
        return;
    }

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

int sendall(int fd, char *buf, int len) {
    int total = 0;
    int bytes_left = len;
    int bytes_send = 0;

    while (total < len) {
        bytes_send = send(fd, buf + total, bytes_left, 0);
        total += bytes_send;
        bytes_left -= bytes_send;
    }

    len = total;

    return bytes_send == -1 ? -1 : 0;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
