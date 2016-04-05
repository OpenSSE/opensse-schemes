//
//  logger.cpp
//  sophos
//
//  Created by Raphael Bost on 05/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "logger.hpp"
#include <iostream>

namespace sse {
    namespace logger
    {
        LoggerSeverity severity__ = INFO;
        std::ostream  null_stream__(0);
        
        void set_severity(LoggerSeverity s)
        {
            severity__ = s;
        }

        
        std::string hex_string(const std::string& in){
            std::ostringstream out;
            for(unsigned char c : in)
            {
                out << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
            }
            return out.str();
        }

        std::ostream& log(LoggerSeverity s){
            if (s >= severity__) {
                return std::cout;
            }else{
                return null_stream__;
            }
        }
    }
}