//
//  utils.hpp
//  sophos
//
//  Created by Raphael Bost on 31/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <sys/stat.h>

uint64_t xor_mask(const uint64_t in, const std::array<uint8_t, 16>& mask);

bool is_file(const std::string& path);
bool is_directory(const std::string& path);
bool exists(const std::string& path);
bool create_directory(const std::string& path, mode_t mode);