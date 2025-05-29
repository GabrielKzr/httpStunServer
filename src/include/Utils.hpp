#ifndef UTILS_HPP
#define UTILS_HPP

// #define CROW_ENABLE_SSL

#include "StunHeaders.hpp"
#include "crow.h"
#include <stdexcept>
#include <cctype>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <nlohmann/json.hpp> // Biblioteca JSON (https://github.com/nlohmann/json)

#pragma once

using json = nlohmann::json;

StunHeader jsonToStunHeader(const crow::json::rvalue& json);
crow::json::wvalue stunHeaderToJson(const StunHeader& header);
void generateUUIDBytes(char uuidArray[33]);

StunHeader jsonNlohmannToStunHeader(const json& json);
json stunHeaderToJsonNlohmann(const StunHeader& header);

XorMappedAddress buildXorMappedAddress(int port, std::string clientIp);
json xorMappedAddressToJsonNlohmann(const XorMappedAddress& xorAddr);

bool jsonContainsUUID(const nlohmann::json& j, const std::string& uuid);

#endif