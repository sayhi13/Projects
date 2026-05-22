#include "sh2parse.h"
#include "sh2macro.h"
#include "sh2net.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

const char* config_path = ".sh2peer.conf\0";
int64_t config_size = -1;
int16_t config_fd = -1;
char* config_ptr = NULL;

const char* options[] = {
	"help\0",
	"set-name=\0",
	"create-single=\0",
	"create-multy=\0",
	"connect=\0",
	"add-white-list=\0",
	"exc-black-list=\0",
	"exit\0"
};

void sigint_exit(int) {
	unload_config(config_ptr, config_fd, config_size);
	printf("\b\b  \n[i] Session finished\n");
	exit(SIGINTED);
}

int main() {
	if ( load_config(config_path, &config_ptr, &config_fd, &config_size) < 0 ) {
		printf(COLORED(RED, "[-] Internal error\n"));
		exit(INTERNAL_ERROR);
	}

	char* name = extract_name(config_ptr);

	if (!name) {
		unload_config(config_ptr, config_fd, config_size);
		printf(COLORED(RED, "[-] Config corrupted\n"));
		exit(CONFIG_CORRUPTED);
	}

	signal(SIGINT, sigint_exit);
	printf(CLEAR_CONSOLE);
	printf("Welcome to sh2peer, %s\n\n[i] Type \"help\" to get manual\n\n", name);
	fflush(stdout);
	
	bool is_exit = false;
	char input[INPUT_MAX_LEN];

	while (!is_exit) {
		memset(input, 0, INPUT_MAX_LEN);
		printf(COLORED(AQUAMARINE, "sh2peer> "));
		fflush(stdout);

		int8_t bytes_read = read(STDIN, input, INPUT_MAX_LEN);

		if (bytes_read < 0) {
			printf("[-] Read error\n");
			exit(INTERNAL_ERROR);
		} else if (bytes_read - 1 == 0) {
			continue;
		} else {
			input[bytes_read - 1] = '\0';

			opt_data* odata = find_option(options, OPTIONS_LEN, OPTION_MAX_LEN, input, INPUT_MAX_LEN);

			if (odata->result < 0) {
				printf("[-] Invalid option\n");
				free(odata);
				continue;
			}

			switch (odata->result) {
				case HELP_OPT: {
					printf("\n[i] Manual : \n\n");
					printf("    set-name=<your name> - setup username\n");
					printf("    create-single=<port> - create chat for 2 peers via <ip> & <port>\n");
					printf("    create-multy=<port>:<max> - create channel for <max> peers\n");
					printf("    connect=<ip>:<port> - connect to <ip> via <port>\n");
					printf("    add-while-list=<ip1>,<ip2> - when you are a server only these ip will can connect\n");
					printf("    exc-white-list=<ip1>,<ip2> - exclude ip from while list\n");
					printf("    exit - finish a session\n\n");
					printf("    if during communicate you are a server and you want to block user - input \"!ban <username>\" to put his ip to the banlist\n");
					printf("    exc-ban-list=<ip1>,<ip2> -  exclude user from banlist (he will be moved to white-list)\n\n");
			
					break;
				}

				case EXIT_OPT: {
					unload_config(config_ptr, config_fd, PAGE_SIZE);
					printf("[i] Session finished\n");
					exit(SUCCESS);
				}

				case SET_NAME_OPT: {
					if (replace_name_buf(name, odata->input) != SUCCESS) {
						printf("[-] Name's length cannot be more than 20 characters\n");
						break;
					}
					
					replace_name_config(config_ptr, &config_size, odata->input);
					break;
				}

				case CREAT_S_OPT: {
					int64_t port = atoi(odata->input);
					int8_t acception_result = -1;
					pthread_t receiver_thread;
					pthread_t sender_thread;

					if (port < 1024 || port > 65535) {
						printf("[-] Invalid port. Available range : [1024 - 65535]\n");
						break;
					}

					if ( create_tcp_server((uint16_t)port) != SUCCESS ) {
						printf("[-] Cannot create server\n");
						break;
					}	

					if (pthread_create(&sender_thread, NULL, sender_worker, name) != 0) {
						printf("[-] Cannot start sender thread\n");
						server_running = 0;
						close(server_fd);
						break;
					} 

					printf(CLEAR_CONSOLE);
					printf(COLORED(YELLOW, "[+] Server started on port "));
					printf("%s\n", odata->input);

					while (server_running) {
						if (is_canonical_tty) {
							setup_non_canonical_tty();
						}

						acception_result = server_accept();

						if (acception_result != SUCCESS) {
							if (acception_result != SERVER_RUNNING_FAIL) {
								printf("[-] Connection accept error\n");
							}

							break;
						}

						if (pthread_create(&receiver_thread, NULL, receiver_worker, NULL) != 0) {
							printf("[-] Cannot start receiver thread\n");
							pthread_cancel(sender_thread);
							server_running = 0;
							client_connect = 0;
							close(client_fd);
							close(server_fd);
							break;
						}
					
						printf(COLORED(PURPLE, "[+] Connection received from : "));
						printf("%s\n\n", inet_ntoa(client.sin_addr));

						pthread_join(receiver_thread, NULL);
					}					

					if (!is_canonical_tty) {
						restore_canonical_tty();
					}

					break;
				}

				case CONNECT_OPT: {
					sep_ip_port* separated = separate_ip_port(odata->input);

					if (!separated) {
						printf("[-] Invalid format ip or port\n");
						break;
					}

					uint64_t port = atoi(separated->port);
					uint32_t ip = 0;
					pthread_t receiver_thread;
					pthread_t sender_thread;

					port = atoi(separated->port);
	
					if (port < 1024 || port > 65535) {
						printf("[-] Invalid port. Available range : [1024 - 65535]\n");
						break;
					}

					if (inet_pton(AF_INET, separated->ip, &ip) <= 0) {
						printf("[-] Invalid ip format\n");
						break;
					}
				
					if ( create_tcp_client(ip, port) != SUCCESS ) {
						printf("[-] Cannot create client. Try again later\n");
						break;
					}

					printf(CLEAR_CONSOLE);
					printf(COLORED(PURPLE, "[i] Connecting to "));
					printf("%s:%s\n", separated->ip, separated->port);
	
					free(separated);
					separated = NULL;

					if ( _client_connect() != SUCCESS ) {
						pthread_cancel(sender_thread);
						server_running = 0;
						client_connect = 0;
						close(client_fd);
						close(server_fd);
						printf("[-] Cannot connect to server\n");
						break;
					} 

					printf(COLORED(YELLOW, "[+] Connected\n\n"));

					if (is_canonical_tty) {
						setup_non_canonical_tty();
					}

					if (pthread_create(&sender_thread, NULL, sender_worker, name) != 0) {
						printf("[-] Cannot start sender thread\n");
						server_running = 0;
						close(server_fd);
						break;
					} 

					if (pthread_create(&receiver_thread, NULL, receiver_worker, NULL) != 0) {
						if (!is_canonical_tty) {
							restore_canonical_tty();
						}

						printf("[-] Cannot start receiver thread\n");
						pthread_cancel(sender_thread);
						server_running = 0;
						client_connect = 0;
						close(client_fd);
						close(server_fd);
						break;
					} 

					pthread_join(receiver_thread, NULL);					

					if (!is_canonical_tty) {
						restore_canonical_tty();
					}

					break;
				}

				default: {
					printf("[i] In developing...\n");
				}
			}

			free(odata);
			odata = NULL;
		}
	}
	
	free(name);
	name = NULL;

	return 0;
}