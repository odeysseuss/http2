#ifndef TCP_H
#define TCP_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <wait.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/// for custom allocators
#define malloc_ malloc
#define calloc_ calloc
#define realloc_ realloc
#define free_ free

#define MAX_EPOLL_EVENTS 1024

typedef struct {
    struct epoll_event ev, events[MAX_EPOLL_EVENTS];
    int epoll_fd;
    int nfds;
} Event;

typedef struct {
    int fd;
    uint32_t addr;
    uint16_t port;
} Listener;

typedef struct {
    int fd;
    int epoll_fd;
    uint32_t addr;
    uint16_t port;
} Conn;

Listener *tcpListen(int port);
Event *tcpPoll(Listener *listener);
Conn *tcpAccept(Listener *listener);
int tcpHandler(Conn *conn, void (*handler)(Conn *conn));
void tcpCloseConn(Conn *conn);
void tcpCloseListener(Listener *listener);

ssize_t tcpRecv(int fd, void *buf, size_t len);
ssize_t tcpSend(int fd, const void *buf, size_t len);

#ifdef TCP_IMPLEMENTATION

static int setSockOpt_(int fd) {
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        return -1;
    }

    return 0;
}

static int setNonBlockingSocket_(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl get");
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl set");
        return -1;
    }

    return 0;
}

static inline Event *getEventPtr_(Listener *listener) {
    return (Event *)(listener + 1);
}

static inline void sigchldHandler_(int s) {
    (void)s;

    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    errno = saved_errno;
}

static int reapDeadProcs_(void) {
    struct sigaction sig;
    sig.sa_handler = sigchldHandler_;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sig, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    return 0;
}

static int tcpEpollInit_(Listener *listener) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        return -1;
    }

    Event *event = getEventPtr_(listener);
    event->epoll_fd = epoll_fd;
    event->ev.data.fd = listener->fd;
    event->ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener->fd, &event->ev) == -1) {
        perror("epoll_ctl listener");
        close(epoll_fd);
        return -1;
    }

    return 0;
}

static int addtoEpollList_(Conn *conn, Listener *listener) {
    if (!listener || !conn) {
        return -1;
    }

    Event *event = getEventPtr_(listener);
    event->ev.data.ptr = conn;
    event->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    if (epoll_ctl(event->epoll_fd, EPOLL_CTL_ADD, conn->fd, &event->ev) == -1) {
        perror("epoll_ctl client");
        return -1;
    }

    return 0;
}

Listener *tcpListen(int port) {
    Listener *listener = (Listener *)malloc_(sizeof(Listener) + sizeof(Event));
    if (!listener) {
        perror("malloc");
        return NULL;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        free_(listener);
        return NULL;
    }

    if (setSockOpt_(fd) == -1) {
        goto clean;
    }

    if (setNonBlockingSocket_(fd) == -1) {
        goto clean;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    listener->fd = fd;
    listener->port = addr.sin_port;
    listener->addr = addr.sin_addr.s_addr;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        goto clean;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        perror("listen");
        goto clean;
    }

    if (reapDeadProcs_() == -1) {
        goto clean;
    }

    if (tcpEpollInit_(listener) == -1) {
        goto clean;
    }

    return listener;

clean:
    close(fd);
    free_(listener);
    return NULL;
}

Event *tcpPoll(Listener *listener) {
    Event *event = getEventPtr_(listener);
    event->nfds =
        epoll_wait(event->epoll_fd, event->events, MAX_EPOLL_EVENTS, -1);
    if (event->nfds == -1) {
        perror("epoll_wait");
        tcpCloseListener(listener);
        return NULL;
    }

    return event;
}

Conn *tcpAccept(Listener *listener) {
    if (!listener) {
        return NULL;
    }

    Conn *conn = (Conn *)malloc_(sizeof(Conn));
    if (!conn) {
        perror("malloc conn");
        return NULL;
    }

    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);
    int conn_fd = accept(listener->fd, (struct sockaddr *)&addr, &size);

    if (conn_fd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NULL;
        }
        perror("accept");
        free_(conn);
        return NULL;
    }

    Event *event = getEventPtr_(listener);
    conn->fd = conn_fd;
    conn->epoll_fd = event->epoll_fd;
    conn->addr = addr.sin_addr.s_addr;
    conn->port = addr.sin_port;

    if (setNonBlockingSocket_(conn_fd) == -1) {
        goto clean;
    }

    if (addtoEpollList_(conn, listener) == -1) {
        goto clean;
    }

    return conn;

clean:
    close(conn_fd);
    free_(conn);
    return NULL;
}

int tcpHandler(Conn *conn, void (*handler)(Conn *conn)) {
    if (!conn || !handler) {
        return -1;
    }

    handler(conn);
    return 0;
}

void tcpCloseConn(Conn *conn) {
    if (!conn) {
        return;
    }

    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL) == -1) {
        perror("epoll_ctl del");
    }
    close(conn->fd);
    free_(conn);
}

void tcpCloseListener(Listener *listener) {
    if (!listener) {
        return;
    }

    Event *event = getEventPtr_(listener);
    close(event->epoll_fd);
    close(listener->fd);
    free_(listener);
}

ssize_t tcpRecv(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf) {
        return -1;
    }

    ssize_t bytes_recv = recv(fd, buf, len, 0);
    if (bytes_recv == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        perror("recv");
        return -1;
    }

    if (bytes_recv == 0) {
        return 0;
    }

    return bytes_recv;
}

ssize_t tcpSend(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf) {
        return -1;
    }

    size_t total = 0;
    size_t bytes_left = len;
    ssize_t bytes_send = 0;

    while (total < len) {
        bytes_send = send(fd, (const char *)buf + total, bytes_left, 0);
        if (bytes_send == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            perror("send");
            return -1;
        }
        if (bytes_send == 0) {
            break;
        }
        total += bytes_send;
        bytes_left -= bytes_send;
    }

    return total;
}

#endif // TCP_IMPLEMENTATION

#undef malloc_
#undef calloc_
#undef realloc_
#undef free_

#ifdef __cplusplus
}
#endif

#endif
