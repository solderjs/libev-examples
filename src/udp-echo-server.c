// Source: http://www.mail-archive.com/libev@lists.schmorp.de/msg00987.html

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ev.h>

#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <unistd.h>

#define DEFAULT_PORT    3333
#define BUF_SIZE        4096

typedef struct {
    ev_io watcher;
    struct sockaddr addr;
    socklen_t addr_len;
    char* buffer;
    size_t buffer_len;
} response_details;

// This callback is called when data is writable on the UDP socket, with
// w->data pointing to a response_details instance.
static void udp_response_cb(EV_P_ ev_io *w, int revents) {
    response_details *r = w->data;

    // Echo the buffer back
    sendto(w->fd, r->buffer, r->buffer_len, 0, &r->addr, r->addr_len);

    // Tell libev not to call this watcher again, because we're freeing it from memory
    ev_io_stop(EV_A_ w);

    free(r->buffer);
    free(r);
}

// This callback is called when data is readable on the UDP socket.
static void udp_cb(EV_P_ ev_io *w, int revents) {
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    char buffer[BUF_SIZE];
    response_details *r;

    puts("udp socket has become readable");
    socklen_t bytes = recvfrom(w->fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*) &addr, (socklen_t *) &addr_len);

    // add a null to terminate the input, as we're going to use it as a string
    buffer[bytes] = '\0';

    printf("udp client said: %s", buffer);

    // Prepare a response_details struct to be passed as w->data to the
    // udp_response_cb callback (that will be called when the socket is writable).
    r = calloc(1, sizeof(response_details));
    memcpy(&r->addr, &addr, sizeof(addr));
    r->addr_len = addr_len;
    r->buffer = calloc(bytes, sizeof(char));
    memcpy(r->buffer, buffer, bytes);
    r->buffer_len = bytes;

    ev_io_init(&r->watcher, udp_response_cb, w->fd, EV_WRITE);
    r->watcher.data = r;
    ev_io_start(EV_A_ &r->watcher);
}

int main(void) {
    struct sockaddr_in addr;
    int sd; // socket descriptor
    int port = DEFAULT_PORT;
    puts("udp_echo server started...");

    // Setup a udp listening socket.
    sd = socket(PF_INET, SOCK_DGRAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
        perror("bind");

    // Do the libev stuff.
    struct ev_loop *loop = ev_default_loop(0);
    ev_io udp_watcher;
    ev_io_init(&udp_watcher, udp_cb, sd, EV_READ);
    ev_io_start(loop, &udp_watcher);
    ev_loop(loop, 0);

    // This point is never reached.
    close(sd);
    return EXIT_SUCCESS;
}
