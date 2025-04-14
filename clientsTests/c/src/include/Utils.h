#include <cjson/cJSON.h>
#include "StunHeaders.h"
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

cJSON* stun_header_to_json(const StunHeader* header);
StunHeader create_stun_request(const uint8_t* uuid);