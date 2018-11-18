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


#pragma once

#include <cstdint>
#include <sys/stat.h>

#include <array>
#include <iomanip>
#include <sstream>
#include <string>

template<size_t N>
uint64_t xor_mask(const uint64_t in, const std::array<uint8_t, N>& mask)
{
    static_assert(N >= 8, "Input array is too small.");

    // Defined for LITTLE ENDIAN arch
    return in ^ (((uint64_t)mask[0]) << 56) ^ (((uint64_t)mask[1]) << 48)
           ^ (((uint64_t)mask[2]) << 40) ^ (((uint64_t)mask[3]) << 32)
           ^ (((uint64_t)mask[4]) << 24) ^ (((uint64_t)mask[5]) << 16)
           ^ (((uint64_t)mask[6]) << 8) ^ (mask[7]);
}


bool is_file(const std::string& path);
bool is_directory(const std::string& path);
bool exists(const std::string& path);
bool create_directory(const std::string& path, mode_t mode);

std::string hex_string(const std::string& in);

template<size_t N>
std::string hex_string(const std::array<uint8_t, N>& in)
{
    std::ostringstream out;
    for (unsigned char c : in) {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint)c;
    }
    return out.str();
}

std::ostream& print_hex(std::ostream& out, const std::string& s);
template<size_t N>
std::ostream& print_hex(std::ostream& out, const std::array<uint8_t, N>& a)
{
    for (unsigned char c : a) {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint)c;
    }
    return out;
}

std::string hex_string(const uint64_t& a);
std::string hex_string(const uint32_t& a);

template<class MapClass>
void write_keyword_map(std::ostream& out, MapClass& kw_map)
{
    for (auto p : kw_map) {
        out << p.first << "       " << std::hex << p.second << "\n";
    }
}

void append_keyword_map(std::ostream&      out,
                        const std::string& kw,
                        uint32_t           index);

template<class MapClass>
bool parse_keyword_map(std::istream& in, MapClass& kw_map)
{
    std::string line, kw, index_string;

    while (std::getline(in, line)) {
        std::stringstream line_stream(line);

        if (!std::getline(line_stream, kw, ' ')) {
            return false;
        }
        if (!std::getline(line_stream, index_string)) {
            return false;
        }
        kw_map.insert(std::make_pair(kw, std::stoul(index_string, NULL, 16)));
    }
    return true;
}