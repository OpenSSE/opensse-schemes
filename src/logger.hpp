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
        
        LoggerSeverity severity();
        void set_severity(LoggerSeverity s);
        std::ostream& log(LoggerSeverity s);
        
        bool set_benchmark_file(const std::string& path);
        std::ostream& log_benchmark();
        
        std::string severity_string(LoggerSeverity s);
    }
}

#ifdef BENCHMARK

#define BENCHMARK_SIMPLE(comment, block) \
    {\
        auto begin = std::chrono::high_resolution_clock::now();\
        block;\
        auto end = std::chrono::high_resolution_clock::now();\
        std::chrono::duration<double, std::milli> time_ms = end - begin; \
        sse::logger::log_benchmark() << (comment) << " " << time_ms.count() << " ms" << std::endl;\
    }

#define BENCHMARK_Q(block, quotient, comment_f) \
{\
auto begin = std::chrono::high_resolution_clock::now(); \
block; \
auto end = std::chrono::high_resolution_clock::now(); \
std::chrono::duration<double, std::milli> time_ms = end - begin; \
{sse::logger::log_benchmark() << comment_f(time_ms.count(), quotient) << std::endl;} \
}

#else
#define BENCHMARK_SIMPLE(comment, block) block;
#define BENCHMARK_Q(block, quotient, comment_f) block;
#endif