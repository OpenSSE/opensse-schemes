//
//  logger.cpp
//  sophos
//
//  Created by Raphael Bost on 05/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "logger.hpp"
#include <iostream>
#include <fstream>
#include <memory>

namespace sse {
    namespace logger
    {
        LoggerSeverity severity__ = INFO;
        std::ostream  null_stream__(0);
        
        std::unique_ptr<std::ofstream> benchmark_stream__;
        
        
        void set_severity(LoggerSeverity s)
        {
            severity__ = s;
        }
        
        bool set_benchmark_file(const std::string& path)
        {
            if (benchmark_stream__) {
                benchmark_stream__->close();
            }
            
            std::ofstream *stream_ptr = new std::ofstream(path);
            
            if (!stream_ptr->is_open()) {
                benchmark_stream__.reset();

                logger::log(logger::ERROR) << "Failed to set benchmark file: " << path << std::endl;

                return false;
            }
            benchmark_stream__.reset(stream_ptr);
            
            return true;
        }
        
        std::ostream& log(LoggerSeverity s){
            if (s >= severity__) {
                return (std::cout << severity_string(s));
            }else{
                return null_stream__;
            }
        }
        
        std::ostream& log_benchmark(){
            if (benchmark_stream__) {
                return *benchmark_stream__;
            }else{
                return std::cout;
            }
        }
        
        std::string severity_string(LoggerSeverity s)
        {
            switch (s) {
                case DBG:
                    return "[DEBUG] - ";
                    break;
                    
                case TRACE:
                    return "[TRACE] - ";
                    break;
                    
                case INFO:
                    return "[INFO] - ";
                    break;
                    
                case WARNING:
                    return "[WARNING] - ";
                    break;
                    
                case ERROR:
                    return "[ERROR] - ";
                    break;
                    
                case CRITICAL:
                    return "[CRITICAL] - ";
                    break;
                    
                default:
                    return "[??] - ";
                    break;
            }
        }

    }
}