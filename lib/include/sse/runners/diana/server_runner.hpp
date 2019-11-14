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

#include <sse/schemes/diana/diana_server.hpp>

#include <grpcpp/grpcpp.h>

#include <mutex>
#include <string>

namespace sse {
namespace diana {

class DianaImpl;

class DianaServerRunner
{
public:
    DianaServerRunner()                         = delete;
    DianaServerRunner(const DianaServerRunner&) = delete;
    DianaServerRunner(DianaServerRunner&&)      = default;

    DianaServerRunner(grpc::ServerBuilder& builder,
                      const std::string&   server_db_path);
    DianaServerRunner(const std::string& server_address,
                      const std::string& server_db_path);


    // as we forward-declare SophosImpl, we cannot use the default destructor
    ~DianaServerRunner();

    void set_async_search(bool flag);

    void wait();
    void shutdown();

private:
    std::unique_ptr<DianaImpl>    service_;
    std::unique_ptr<grpc::Server> server_;
};

} // namespace diana
} // namespace sse
