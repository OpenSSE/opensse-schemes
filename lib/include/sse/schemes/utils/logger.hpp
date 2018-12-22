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

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <iomanip>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>

namespace sse {
namespace logger {

std::shared_ptr<spdlog::logger> logger();
void set_logger(const std::shared_ptr<spdlog::logger>& logger);

void set_logging_level(spdlog::level::level_enum log_level);

} // namespace logger

class Benchmark
{
public:
    static void set_benchmark_file(const std::string& path);

    explicit Benchmark(std::string format);
    Benchmark() = delete;

    void stop();
    void stop(size_t count);

    inline void set_count(size_t c)
    {
        count_ = c;
    }

    virtual ~Benchmark();

private:
    static std::shared_ptr<spdlog::logger> benchmark_logger_;

    std::string                                    format_;
    size_t                                         count_;
    bool                                           stopped_;
    std::chrono::high_resolution_clock::time_point begin_;
    std::chrono::high_resolution_clock::time_point end_;
};

class SearchBenchmark : public Benchmark
{
public:
    explicit SearchBenchmark(std::string message);
};

} // namespace sse