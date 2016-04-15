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

#include <sstream>
#include <string>
#include <iomanip>

uint64_t xor_mask(const uint64_t in, const std::array<uint8_t, 16>& mask);

bool is_file(const std::string& path);
bool is_directory(const std::string& path);
bool exists(const std::string& path);
bool create_directory(const std::string& path, mode_t mode);

std::string hex_string(const std::string& in);

template <size_t N> std::string hex_string(const std::array<uint8_t,N>& in) {
    std::ostringstream out;
    for(unsigned char c : in)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
    }
    return out.str();
}

std::ostream& print_hex(std::ostream& out, const std::string &s);
template <size_t N>
std::ostream& print_hex(std::ostream& out, const std::array<uint8_t,N> &a) {
    for(unsigned char c : a)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
    }
    return out;
}

template <class MapClass>
void write_keyword_map(std::ostream& out, MapClass& kw_map)
{
    for (auto p : kw_map) {
        out << p.first << "       " << std::hex << p.second << "\n";
    }

}

void append_keyword_map(std::ostream& out, const std::string &kw, uint32_t index);

template <class MapClass>
bool parse_keyword_map(std::istream& in, MapClass& kw_map)
{
    std::string line, kw, index_string;
    
    while (std::getline(in, line)) {
        std::stringstream line_stream(line);
        
        if(!std::getline(line_stream, kw, ' '))
        {
            return false;
        }
        if (!std::getline(line_stream,index_string)) {
            return false;
        }
        kw_map.insert(std::make_pair(kw,std::stoul(index_string, NULL, 16)));
    }
    return true;
}