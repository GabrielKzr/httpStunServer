#include <cjson/cJSON.h>
#include "StunHeaders.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

void stun_header_to_json(cJSON* json, const StunHeader* header);
void create_stun_request(StunHeader* header, const unsigned char* uuid, int type);
int save_uuid_file(char *uuid_hex_str);
int remove_uuid_file();
int getUuidFromFile(char* buffer, size_t size, char* path);
int unxor_ip(char* ipXor, char* ipOut);
int unxor_port(int xorPort);