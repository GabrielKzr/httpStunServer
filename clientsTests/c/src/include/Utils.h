#include <cjson/cJSON.h>
#include "StunHeaders.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

cJSON* stun_header_to_json(const StunHeader* header);
StunHeader create_stun_request(const uint8_t* uuid, int type);
int hex_to_bytes(const char* hex, unsigned char* output, size_t output_len);
void bytes_to_hex(const uint8_t* input, size_t len, char* output);
int save_uuid_file(uint8_t *uuid_hex_str);