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

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/null_sink.h>
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

void set_logger(const std::shared_ptr<spdlog::logger>& logger)
{
    if (logger) {
        shared_logger_ = logger;
    } else {
        shared_logger_
            = spdlog::create<spdlog::sinks::null_sink_mt>("null_logger");
    }
}

void set_logging_level(spdlog::level::level_enum log_level)
{
    logger()->set_level(log_level);
}
} // namespace logger

std::shared_ptr<spdlog::logger> Benchmark::benchmark_logger_(nullptr);

void Benchmark::set_benchmark_file(const std::string& path)
{
    benchmark_logger_
        = spdlog::basic_logger_mt<spdlog::async_factory>("benchmark", path);
    benchmark_logger_->set_level(spdlog::level::trace);

    benchmark_logger_->set_pattern("[%Y-%m-%d %T.%e] %v");
}

// cppcheck-suppress passedByValue
Benchmark::Benchmark(std::string format)
    : format_(std::move(format)), count_(0), stopped_(false),
      begin_(std::chrono::high_resolution_clock::now())
{
}

void Benchmark::stop()
{
    if (!stopped_) {
        end_ = std::chrono::high_resolution_clock::now();
    }
}

void Benchmark::stop(size_t count)
{
    if (!stopped_) {
        end_   = std::chrono::high_resolution_clock::now();
        count_ = count;
    }
}

Benchmark::~Benchmark()
{
    stop();

    std::chrono::duration<long double, std::milli> time_ms = end_ - begin_;

    auto time_per_item = time_ms;

    if (count_ > 1) {
        time_per_item /= static_cast<long double>(count_);
    }

    if (benchmark_logger_) {
        benchmark_logger_->trace(
            format_.c_str(), count_, time_ms.count(), time_per_item.count());
    }
}

constexpr auto search_JSON_begin
    = "{{ \"message\" : \""; // double { to escape it in fmt
constexpr auto search_JSON_end
    = "\", \"items\" : {0}, \"time\" : {1}, \"time/item\" : {2} }}";

// cppcheck-suppress passedByValue
SearchBenchmark::SearchBenchmark(std::string message)
    : Benchmark(search_JSON_begin + std::move(message) + search_JSON_end)
{
}
} // namespace sse