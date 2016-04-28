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