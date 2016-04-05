//
//  utils.cpp
//  sophos
//
//  Created by Raphael Bost on 31/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
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

void print_hex(std::ostream& out, const std::string &s)
{
//    for (unsigned char c : s) {
//        out << std::hex << std::setw(2) << std::setfill('0') << (uint)c;
//    }
    for(unsigned char c : s)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
    }

}
