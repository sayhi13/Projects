/* Format output */
#define COLORED(color, msg) "\x1b%s%s\x1b[0m", color, msg
#define DEBUG(msg) printf("[DEBUG] %s\n", msg) 
#define CLEAR_CONSOLE "\x1b[2J\x1b[H"
#define CLEAR_STRING "\r\x1b[K"

/* Colors for format input */
#define RED "[31m"
#define AQUAMARINE "[32m"
#define YELLOW "[33m"
#define BLUE "[34m"
#define PURPLE "[35m"
#define ORANGE "[93m"

/* Options index */
#define HELP_OPT 0
#define SET_NAME_OPT 1
#define CREAT_S_OPT 2
#define CREAT_M_OPT 3
#define CONNECT_OPT 4
#define ADD_WHITE_LIST_OPT 5
#define ADD_BLACK_LIST_OPT 6
#define EXIT_OPT 7
#define OPTIONS_LEN 8

/* Main length-constants */
#define MSG_MAX_LEN 512
#define NAME_MAX_LEN 22
#define DEF_CONFIG_LEN 48
#define PAGE_SIZE 4096
#define INPUT_MAX_LEN 40
#define OPTION_MAX_LEN 14
#define IP_MAX_LEN 15
#define PORT_MAX_LEN 5

/* File descriptors */
#define STDIN 0
#define STDOUT 1

/* status codes (errors == terminate / fails == continue loop) */
#define SUCCESS 1
#define FIELD_NOT_FOUND 0
#define OPTION_NOT_FOUND -1
#define STR_TERM_NOT_FOUND -2

// [syscalls]
#define OPEN_ERROR -1
#define MMAP_ERROR -2
#define CLOSE_ERROR -3
#define MUNMAP_ERROR -4
#define STAT_ERROR -5
#define FTRUNCATE_ERROR -6

// [user functions]
#define NAME_LEN_FAIL 2
#define SOCKET_FAIL 3
#define BIND_FAIL 4
#define LISTEN_FAIL 5
#define ACCEPT_FAIL 6
#define SEND_FAIL 7
#define RECV_FAIL 8
#define READ_FAIL 9
#define CONNECT_FAIL 10
#define FORMAT_INPUT_FAIL 11
#define SETSOCKOPT_FAIL 12
#define SELECT_FAIL 13
#define SERVER_RUNNING_FAIL 14

// [termination status codes
#define INTERNAL_ERROR -10
#define CONFIG_CORRUPTED -20
#define SIGINTED -30

/* Other constants */
#define NAME_FIELD_OFFSET 6
#define BACKLOG 10
#define NC_SIGINT 3
#define CLIENT 0
#define SERVER 1