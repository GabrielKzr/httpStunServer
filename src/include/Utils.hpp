#ifndef UTILS_HPP
#define UTILS_HPP

#include "StunHeaders.hpp"
#include "crow.h"
#include <stdexcept>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <nlohmann/json.hpp> // Biblioteca JSON (https://github.com/nlohmann/json)

#pragma once

using json = nlohmann::json;

StunHeader jsonToStunHeader(const crow::json::rvalue& json);
crow::json::wvalue stunHeaderToJson(const StunHeader& header);
void generateUUIDBytes(uint8_t uuidArray[16]);

StunHeader jsonNlohmannToStunHeader(const json& json);
json stunHeaderToJsonNlohmann(const StunHeader& header);

XorMappedAddress buildXorMappedAddress(int port, std::string clientIp);
json xorMappedAddressToJsonNlohmann(const XorMappedAddress& xorAddr);

std::string base64_encode(const unsigned char* bytes, size_t length);
std::string base64_decode(const std::string& encoded_string);

void hex_to_bytes(const std::string& hex, uint8_t* output, size_t output_len);
std::string bytes_to_hex(const uint8_t* input, size_t len);

#endif