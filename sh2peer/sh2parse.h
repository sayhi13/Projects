#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include "sh2macro.h"

typedef struct _opt_data {
	int8_t result;
	char* input;
} opt_data;

typedef struct _sep_ip_port {
	char* ip;
	char* port;
} sep_ip_port;

const char* default_config = "username\n\tunknown;\n\nip-white-list\n\nip-ban-list\n\n\0";

int64_t get_file_size(const char* path) {
	struct stat file_stat;

	if (stat(path, &file_stat) < 0) {
		return STAT_ERROR;
	}

	return file_stat.st_size;
}

int8_t load_config(const char* path, char** pptr, int16_t* fd, int64_t* file_size) {
	if ( (*fd = open(path, O_RDWR, 0o600)) < 0 ) {
		if ( (*fd = open(path, O_RDWR | O_CREAT, 0o600)) < 0 ) {
			return OPEN_ERROR;
		}		

		write(*fd, default_config, DEF_CONFIG_LEN);
	}

	if ( (*file_size = get_file_size(path)) < 0 ) {
		return STAT_ERROR;
	}

	uint64_t truncated_size = (*file_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	if (ftruncate(*fd, truncated_size) < 0) {
		close(*fd);
		return FTRUNCATE_ERROR;
	}

	if ( (*pptr = mmap(NULL, truncated_size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0)) == NULL ) {
		close(*fd);
		return MMAP_ERROR;
	}

	//DEBUG("config loaded\n");

	return SUCCESS;
}

int8_t unload_config(char* pptr, int16_t fd, uint16_t file_size) {
	uint64_t truncated_size = (file_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	//printf("file size %d\n", file_size);

	if ( munmap(pptr, truncated_size) < 0 ) {
		return MUNMAP_ERROR;
	}

	if ( ftruncate(fd, file_size) < 0 ) {
		return FTRUNCATE_ERROR;
	}

	if ( close(fd) < 0 ) {
		return CLOSE_ERROR;
	}

	//DEBUG("config unloaded\n");

	return SUCCESS;
}

uint64_t strnlen_until(const char* str, const char* term, uint64_t str_len, uint64_t term_len) {
	for (uint64_t idx = 0; idx < str_len; ++idx) {
		if (memcmp(str + idx, term, term_len) == 0) {
			//DEBUG("strlen calculated\n");
			return idx;
		}
	}

	return STR_TERM_NOT_FOUND;
}

char* find_field(const char* src, const char* patt, const uint64_t offs) {
	char* entry = strstr(src, patt);

	if (entry) {
		return entry + offs;
	}

	return FIELD_NOT_FOUND;
}

opt_data* find_option(const char** options, uint64_t options_len, uint64_t max_option_len, const char* input, uint64_t max_input_len) {
	opt_data* odata = (opt_data*)malloc(sizeof(opt_data));
	char* equ_sym = strchr(input, '=');

	if (!odata) {
		return NULL;
	}

	uint64_t input_len = strnlen(input, max_input_len);

	for (uint64_t idx = 0; idx < options_len; ++idx) {
		uint64_t option_len = strnlen(options[idx], max_option_len);

		if (!equ_sym) {
			++option_len;
		}

		if (memcmp(options[idx], input, option_len) == 0) {
			//printf("opt %s found\n", input);
			odata->result = idx;

			if (equ_sym) {
				odata->input = (char*)(input + option_len);
			} else {
				odata->input = (char*)input;
			}

			return odata;
		}
	}

	//printf("opt %s not found", input);
	odata->result = OPTION_NOT_FOUND;
	odata->input = NULL;

	return odata;
} 

char* extract_name(const char* config) {
	char* parsed_name = find_field(config, "name", NAME_FIELD_OFFSET);

	if (parsed_name == FIELD_NOT_FOUND) {
		return FIELD_NOT_FOUND;
	}

	//DEBUG("name found\n");

	uint64_t parsed_name_len = strnlen_until(parsed_name, ";",  NAME_MAX_LEN, 1);

	if (parsed_name_len > 20 || parsed_name_len == STR_TERM_NOT_FOUND) {
		//DEBUG("long name\n");
		return NULL;
	}

	char* extracted_name = malloc(parsed_name_len + 1);
	memset(extracted_name, 0, parsed_name_len + 1);
	memcpy(extracted_name, parsed_name, parsed_name_len);

	//DEBUG("name parsed\n");

	return extracted_name;
}

int8_t replace_name_buf(char* current_name, char* new_name) {
	uint8_t new_name_len = strnlen(new_name, NAME_MAX_LEN);

	if (new_name_len > 20) {
		return NAME_LEN_FAIL;
	}

	current_name = realloc(current_name, new_name_len + 1);
	memset(current_name, 0, new_name_len + 1);
	memcpy(current_name, new_name, new_name_len);

	return SUCCESS;
}

int8_t replace_name_config(char* config, int64_t* config_size, char* new_name) {
	char* cfg_name = find_field(config, "name", NAME_FIELD_OFFSET);
	uint64_t cfg_name_len = strnlen_until(cfg_name, ";", NAME_MAX_LEN, 1);
	uint64_t new_name_len = strnlen(new_name, NAME_MAX_LEN);

	if (new_name_len > 20) {
		return NAME_LEN_FAIL;
	}

	int64_t padding = new_name_len - cfg_name_len;

	strcpy(cfg_name + cfg_name_len + padding, cfg_name + cfg_name_len);
	strcpy(cfg_name, new_name);
	*(cfg_name + new_name_len) = ';';
	*config_size += padding;

	//printf("cfg = %d | new = %d | padd = %d | size = %d\n", cfg_name_len, new_name_len, padding, *config_size);

	return SUCCESS;
}

sep_ip_port* separate_ip_port(char* buffer) {
	sep_ip_port* separated = (sep_ip_port*)malloc(sizeof(sep_ip_port));
	uint8_t buf_len = strnlen(buffer, IP_MAX_LEN + PORT_MAX_LEN + 1);
	uint8_t sep_idx = 0;

	for (uint8_t i = 0; i < IP_MAX_LEN && i < buf_len ; ++i) {
		if (buffer[i] == ':') {
			sep_idx = i;
			break;
		}
	}

	if (sep_idx == 0) {
		return NULL;
	}

	buffer[sep_idx] = '\0';

	separated->ip = buffer;
	separated->port = buffer + sep_idx + 1;

	return separated;
}

/*
char* get_field_records(const char* first_record) {
	
}
*/