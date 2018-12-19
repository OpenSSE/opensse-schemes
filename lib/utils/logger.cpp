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

#include <sse/schemes/utils/logger.hpp>

#include <spdlog/sinks/stdout_color_sinks.h>

#include <fstream>
#include <iostream>
#include <memory>

namespace sse {
namespace logger {

std::shared_ptr<spdlog::logger> shared_logger_(nullptr);

std::shared_ptr<spdlog::logger> logger()
{
    if (!shared_logger_) {
        // initialize the logger
        shared_logger_ = spdlog::stderr_color_mt("console");
    }
    return shared_logger_;
}

void set_logging_level(spdlog::level::level_enum log_level)
{
    logger()->set_level(log_level);
}

// bool                           benchmark_stream_set__{false};
std::unique_ptr<std::ostream> benchmark_stream__;

bool set_benchmark_file(const std::string& path)
{
    std::unique_ptr<std::ostream> stream(new std::ofstream(path));

    if (!(dynamic_cast<std::ofstream*>(stream.get())->is_open())) {
        logger::logger()->error("Failed to set benchmark file: " + path);

        return false;
    }

    benchmark_stream__ = std::move(stream);

    return true;
}

std::ostream& log_benchmark()
{
    if (!benchmark_stream__) {
        // set the benchmark stream to the null stream
        benchmark_stream__.reset(new std::ostream(nullptr));
    }
    return *benchmark_stream__;
}

} // namespace logger
} // namespace sse