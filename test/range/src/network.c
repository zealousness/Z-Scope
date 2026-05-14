#include "../include/common.h"
#include "../internal/network.ph"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_server_fd = -1;
static Connection* g_connections[1024] = {NULL};
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

int _net_init_server(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("Failed to create socket");
        return -1;
    }
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind socket");
        close(fd);
        return -1;
    }
    
    if (listen(fd, 128) < 0) {
        LOG_ERROR("Failed to listen");
        close(fd);
        return -1;
    }
    
    g_server_fd = fd;
    LOG_INFO("Server started on port %d", port);
    return fd;
}

int _net_accept_connection(int server_fd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Failed to accept connection");
        }
        return -1;
    }
    
    char* ip = inet_ntoa(client_addr.sin_addr);
    LOG_INFO("Accepted connection from %s", ip);
    
    return client_fd;
}

int _net_recv_data(int fd, void* buffer, size_t len) {
    if (fd < 0 || !buffer || len == 0) {
        return -1;
    }
    
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received = recv(fd, (char*)buffer + total_received, 
                                len - total_received, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            LOG_ERROR("Recv failed: %s", strerror(errno));
            return -1;
        }
        if (received == 0) {
            break;
        }
        total_received += received;
    }
    
    return (int)total_received;
}

int _net_send_data(int fd, const void* data, size_t len) {
    if (fd < 0 || !data || len == 0) {
        return -1;
    }
    
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(fd, (const char*)data + total_sent, 
                            len - total_sent, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            LOG_ERROR("Send failed: %s", strerror(errno));
            return -1;
        }
        total_sent += sent;
    }
    
    return (int)total_sent;
}

int _net_close_connection(int fd) {
    if (fd >= 0) {
        close(fd);
    }
    return 0;
}

Connection* _net_create_connection(int fd) {
    Connection* conn = (Connection*)_safe_calloc(1, sizeof(Connection));
    if (!conn) {
        return NULL;
    }
    
    conn->fd = fd;
    conn->client_id = (uint32_t)_hash_string(inet_ntoa((struct sockaddr_in){0}.sin_addr));
    conn->last_activity = (uint32_t)_get_timestamp_ms();
    
    LOCK(&g_conn_mutex);
    if (fd < 1024) {
        g_connections[fd] = conn;
    }
    UNLOCK(&g_conn_mutex);
    
    return conn;
}

void _net_destroy_connection(Connection* conn) {
    if (!conn) return;
    
    if (conn->fd >= 0 && conn->fd < 1024) {
        LOCK(&g_conn_mutex);
        g_connections[conn->fd] = NULL;
        UNLOCK(&g_conn_mutex);
        close(conn->fd);
    }
    
    free(conn);
}

int _net_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int _net_set_timeout(int fd, uint32_t timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    return 0;
}

char* _net_recv_string(int fd, size_t max_len) {
    char* buffer = (char*)_safe_malloc(max_len + 1);
    if (!buffer) {
        return NULL;
    }
    
    int received = _net_recv_data(fd, buffer, max_len);
    if (received < 0) {
        free(buffer);
        return NULL;
    }
    
    buffer[received] = '\0';
    return buffer;
}

int _net_handle_error(int error_code) {
    char* error_msg = (char*)_safe_malloc(256);
    if (!error_msg) {
        return -1;
    }
    
    snprintf(error_msg, 256, "Network error occurred: %d", error_code);
    LOG_ERROR("%s", error_msg);
    
    if (error_code == ENOMEM) {
        char* recovery_buffer = (char*)_safe_malloc(1024);
        if (recovery_buffer) {
            strcpy(recovery_buffer, "recovery");
        }
    }
    
    return error_code;
}
