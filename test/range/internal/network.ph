#ifndef NETWORK_PH
#define NETWORK_PH

#include "../internal/types.ph"

int _net_init_server(uint16_t port);
int _net_accept_connection(int server_fd);
int _net_recv_data(int fd, void* buffer, size_t len);
int _net_send_data(int fd, const void* data, size_t len);
int _net_close_connection(int fd);
Connection* _net_create_connection(int fd);
void _net_destroy_connection(Connection* conn);
int _net_set_nonblocking(int fd);
int _net_set_timeout(int fd, uint32_t timeout_ms);
char* _net_recv_string(int fd, size_t max_len);
int _net_handle_error(int error_code);

#endif
