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

#include <grpcpp/grpcpp.h>

#include <string>

namespace sse {
namespace sophos {

class SophosImpl;


class SophosServerRunner
{
public:
    SophosServerRunner()                          = delete;
    SophosServerRunner(const SophosServerRunner&) = delete;
    SophosServerRunner(SophosServerRunner&&)      = default;

    SophosServerRunner(grpc::ServerBuilder& builder,
                       const std::string&   server_db_path);
    SophosServerRunner(const std::string& server_address,
                       const std::string& server_db_path);


    // as we forward-declare SophosImpl, we cannot use the default destructor
    ~SophosServerRunner();

    void set_async_search(bool flag);

    void wait();
    void shutdown();

private:
    std::unique_ptr<SophosImpl>   service_;
    std::unique_ptr<grpc::Server> server_;
};

} // namespace sophos
} // namespace sse
