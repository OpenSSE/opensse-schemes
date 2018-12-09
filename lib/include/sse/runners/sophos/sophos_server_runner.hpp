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

#include <grpc++/server.h>
#include <grpc++/server_builder.h>

#include <string>

namespace sse {
namespace sophos {

class SophosImpl;

std::unique_ptr<grpc::Server> build_sophos_server(
    grpc::ServerBuilder&            builder,
    const std::string&              server_db_path,
    bool                            async_search,
    std::unique_ptr<grpc::Service>& service);

void run_sophos_server(const std::string& server_address,
                       const std::string& server_db_path,
                       grpc::Server**     server_ptr,
                       bool               async_search);

void run_sophos_server(grpc::ServerBuilder&         builder,
                       const std::string&           server_db_path,
                       grpc::Server**               server_ptr,
                       bool                         async_search,
                       const std::function<void()>& server_started_callback);
} // namespace sophos
} // namespace sse
