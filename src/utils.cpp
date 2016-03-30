//
//  utils.cpp
//  sophos
//
//  Created by Raphael Bost on 31/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "utils.hpp"

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