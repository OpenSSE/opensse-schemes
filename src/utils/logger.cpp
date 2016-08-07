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
        
        LoggerSeverity severity()
        {
            return severity__;
        }

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