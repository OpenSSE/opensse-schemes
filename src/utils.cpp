//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#include "utils.hpp"

#include <sys/stat.h>
#include <iostream>
#include <iomanip>

uint64_t xor_mask(const uint64_t in, const std::array<uint8_t, 16>& mask)
{
    // Defined for LITTLE ENDIAN arch
    return in   ^ (((uint64_t)mask[0]) << 56)
                ^ (((uint64_t)mask[1]) << 48)
                ^ (((uint64_t)mask[2]) << 40)
                ^ (((uint64_t)mask[3]) << 32)
                ^ (((uint64_t)mask[4]) << 24)
                ^ (((uint64_t)mask[5]) << 16)
                ^ (((uint64_t)mask[6]) << 8)
                ^ (mask[7]);
}


bool is_file(const std::string& path)
{
    struct stat sb;
    
    if (stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode))
    {
        return true;
    }
    return false;
}

bool is_directory(const std::string& path)
{
    struct stat sb;
    
    if (stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return true;
    }
    return false;
}

bool exists(const std::string& path)
{
    struct stat sb;
    
    if (stat(path.c_str(), &sb) == 0)
    {
        return true;
    }
    return false;
}

bool create_directory(const std::string& path, mode_t mode)
{
    if (mkdir(path.data(),mode) != 0) {
        return false;
    }
    return true;
}

std::string hex_string(const std::string& in){
    std::ostringstream out;
    for(unsigned char c : in)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
    }
    return out.str();
}

std::ostream& print_hex(std::ostream& out, const std::string &s)
{
    for(unsigned char c : s)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
    }
    
    return out;
}

void append_keyword_map(std::ostream& out, const std::string &kw, uint32_t index)
{
    out << kw << "       " << std::hex << index << "\n";
}