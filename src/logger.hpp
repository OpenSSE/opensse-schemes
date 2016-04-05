//
//  logger.hpp
//  sophos
//
//  Created by Raphael Bost on 05/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <array>
#include <iomanip>

namespace sse {
    namespace logger
    {
        typedef enum{
            DBG         = 00,
            TRACE       = 10,
            INFO        = 20,
            WARNING     = 30,
            ERROR       = 40,
            CRITICAL    = 50
        } LoggerSeverity;
        
        void set_severity(LoggerSeverity s);
        std::ostream& log(LoggerSeverity s);

        std::string hex_string(const std::string& in);
        
        template <size_t N> std::string hex_string(const std::array<uint8_t,N>& in) {
            std::ostringstream out;
            for(unsigned char c : in)
            {
                out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
            }
            return out.str();
        }
    }
}
