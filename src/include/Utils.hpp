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

#endif