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

#include <google/protobuf/empty.pb.h>
#include <grpc/grpc.h>

#include <memory>
#include <utility>

namespace sse {
namespace sophos {

struct update_tag_type
{
    std::unique_ptr<google::protobuf::Empty> reply;
    std::unique_ptr<grpc::Status>            status;
    std::unique_ptr<size_t>                  index;
};

} // namespace sophos
} // namespace sse