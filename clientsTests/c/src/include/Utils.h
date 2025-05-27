#include <cjson/cJSON.h>
#include "StunHeaders.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

void stun_header_to_json(cJSON* json, const StunHeader* header);
void create_stun_request(StunHeader* header, const uint8_t* uuid, int type);
int hex_to_bytes(const char* hex, unsigned char* output, size_t output_len);
void bytes_to_hex(const uint8_t* input, size_t len, char* output);
int save_uuid_file(uint8_t *uuid_hex_str);
int remove_uuid_file();
int getUuidFromFile(char* buffer, size_t size, char* path);
int unxor_ip(char* ipXor, char* ipOut);
int unxor_port(int xorPort);