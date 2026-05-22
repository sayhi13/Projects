#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "sh2macro.h"
#include "sh2tty.h"

char sender_buf[MSG_MAX_LEN];
uint16_t sender_idx = 0;

char receiver_buf[MSG_MAX_LEN];

volatile sig_atomic_t server_running = 0;
volatile sig_atomic_t client_connect = 0;

int8_t whoami = -1;

pthread_mutex_t chat_mutex = PTHREAD_MUTEX_INITIALIZER;

int16_t server_fd = -1;
int16_t client_fd = -1;

struct sockaddr_in server;
struct sockaddr_in client;

void peer_stop() {
	server_running = 0;
	client_connect = 0;

	close(client_fd);
	close(server_fd);

	client_fd = -1;
	server_fd = -1;

	if (whoami == SERVER) {
		printf(COLORED(ORANGE, "\n[i] Server stopped\n"));
	} else if (whoami == CLIENT) {
		printf(COLORED(ORANGE, "\n[i] You disconnected\n"));
	}

	whoami = -1;
}

void peer_disconnect() {
	if (whoami == SERVER) {
		client_connect = 0;
		close(client_fd);
		client_fd = -1;

		printf(COLORED(BLUE, "\n[i] "));
		printf("%s", inet_ntoa(client.sin_addr));
		printf(COLORED(BLUE, " disconnected\n"));
	} else if (whoami == CLIENT) {
		server_running = 0;
		client_connect = 0;
		close(client_fd);
		close(server_fd);
		client_fd = -1;
		server_fd = -1;
		whoami = -1;

		printf(COLORED(RED, "\n[-] Connection refused by the server\n"));
	}
}

int16_t create_tcp_server(uint16_t port) {	
	if ( (server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		return SOCKET_FAIL;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = INADDR_ANY;
	memset(server.sin_zero, 0, 8);

	if ( bind(server_fd, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0 ) {
		close(server_fd);
		return BIND_FAIL;
	}

	if ( listen(server_fd, BACKLOG) < 0 ) {
		close(server_fd);
		return LISTEN_FAIL;
	}

	server_running = 1;
	whoami = SERVER;
	return SUCCESS;
}

int16_t server_accept() {
	uint64_t sockaddr_in_size = 16;
	int32_t is_received = 0;
	struct timeval tv;
	fd_set readfds;

	while (server_running) {
		if (server_fd < 0) {
			return SERVER_RUNNING_FAIL;
		}

		tv.tv_sec = 0;
		tv.tv_usec = 500000;

		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);

		if ( (is_received = select(server_fd + 1, &readfds, NULL, NULL, &tv)) < 0 ) {
			close(server_fd);
			server_fd = -1;
			server_running = 0;
			whoami = -1;
			return SELECT_FAIL;
		}

		if (is_received > 0 && server_fd > 0) {
			if ( (client_fd = accept(server_fd, (struct sockaddr*)&client, (socklen_t*)&sockaddr_in_size)) < 0 ) {
				close(server_fd);
				server_fd = -1;
				server_running = 0;
				whoami = -1;
				return ACCEPT_FAIL;
			} 
			break;
		}
		usleep(200000);
	}

	if (client_fd < 0) {
		return SERVER_RUNNING_FAIL;
	}

	tv.tv_sec = 0;
	tv.tv_usec = 500000;

	if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) < 0) {
		close(client_fd);
		close(server_fd);
		client_fd = -1;
		server_fd = -1;
		server_running = 0;
		whoami = -1;
		return SETSOCKOPT_FAIL;
	}

	client_connect = 1;
	return SUCCESS;
}

int16_t create_tcp_client(uint32_t ip, uint16_t port) {
	if ( (client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		return SOCKET_FAIL;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = ip;
	memset(server.sin_zero, 0, 8);

	whoami = CLIENT;
	return SUCCESS;
}

int16_t _client_connect() {
	if ( connect(client_fd, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0 ) {
		close(client_fd);
		client_fd = -1;
		whoami = -1;
		return CONNECT_FAIL;
	}

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 500000;

	if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) < 0) {
		close(client_fd);
		client_fd = -1;
		whoami = -1;
		return SETSOCKOPT_FAIL;
	}
	
	server_running = 1;
	client_connect = 1;
	return SUCCESS;
}

void rewrite_screen() {
	printf(CLEAR_STRING);
	printf("%s", sender_buf);
	fflush(stdout);
}

/* void* arg == char* name */
void* sender_worker(void* arg) {
	char* sender_name = (char*)arg;
	int16_t result = 0;
	char ch = 0;

	memset(sender_buf, 0, MSG_MAX_LEN);

	snprintf(sender_buf, NAME_MAX_LEN, "<%s> ", sender_name);
	uint16_t sender_buf_offs = strnlen(sender_name, NAME_MAX_LEN) + 3;
	uint16_t sender_msg_size = MSG_MAX_LEN - sender_buf_offs - 1;
	char* sender_msg_buf = sender_buf + sender_buf_offs;
	sender_idx = sender_buf_offs;

	fflush(stdout);

	while (server_running) {
		if (!client_connect) {
			result = read(STDIN, &ch, 1);

			if (result == 1) {
				if (ch == NC_SIGINT) {
					peer_stop();
					return NULL;
				}
			}

			/*
			printf(CLEAR_STRING);
			fflush(stdout);
			*/

			usleep(10000);
			continue;
		}

		result = read(STDIN, &ch, 1);

		if (result < 0) {
			return (void*)READ_FAIL;		
		} else if (result > 0) {
			switch (ch) {
				case '\n':
				case '\r': {
					pthread_mutex_lock(&chat_mutex);

					if ( send(client_fd, sender_buf, sender_idx + 1, 0) != sender_idx + 1 ) {
						return (void*)SEND_FAIL;
					}

					pthread_mutex_unlock(&chat_mutex);

					memset(sender_msg_buf, 0, sender_msg_size);
					sender_idx = sender_buf_offs;
					putchar('\n');
					break;
				}

				case 127:
				case '\b': {
					if (sender_idx < sender_buf_offs + 1) {
						break;
					}

					sender_buf[--sender_idx] = '\0';
					break;
				}

				/* SIGINT is turning to 0x3 on noncanonical tty mode */
				case NC_SIGINT: {
					peer_stop();
					return NULL;
				}

				default: {
					if (ch == 0x1b) {
						getchar();
						getchar();
						break;
					}

					if (sender_idx > MSG_MAX_LEN - 1) {
						break;
					}

					sender_buf[sender_idx++] = ch;
					break;
				}
			}

		} else {
			usleep(20000);
		}

		if (server_running) {
			rewrite_screen();
		}
	}

	return NULL;
}

/* void* arg = dummy */
void* receiver_worker(void* arg) {
	int16_t result = 0;

	while (server_running && client_connect) {
		memset(receiver_buf, 0, MSG_MAX_LEN);

		result = recv(client_fd, receiver_buf, MSG_MAX_LEN, 0);

		if (result < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(200000);
				continue;
			}
		} else if (result == 0) {
			peer_disconnect();
			printf(CLEAR_STRING);
			return NULL;
		}

		pthread_mutex_lock(&chat_mutex);

		printf(CLEAR_STRING);
		printf("%s\n", receiver_buf);
		rewrite_screen();
		
		pthread_mutex_unlock(&chat_mutex);
	}

	return NULL;
}
