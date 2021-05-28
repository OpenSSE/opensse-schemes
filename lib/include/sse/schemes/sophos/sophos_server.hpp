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

#include <sse/schemes/sophos/sophos_common.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/prf.hpp>
#include <sse/crypto/tdp.hpp>

#include <array>
#include <fstream>
#include <functional>
#include <string>

namespace sse {
namespace sophos {


class SophosServer
{
public:
    SophosServer(const std::string& db_path, const std::string& tdp_pk);

    std::string public_key() const;

    std::list<index_type> search(SearchRequest& req);
    void                  search_callback(SearchRequest&                         req,
                                          const std::function<void(index_type)>& post_callback);

    std::list<index_type> search_parallel(SearchRequest& req,
                                          uint8_t        access_threads);
    std::list<index_type> search_parallel_light(SearchRequest& req,
                                                uint8_t        thread_count);

    void search_parallel_callback(SearchRequest&                  req,
                                  std::function<void(index_type)> post_callback,
                                  uint8_t rsa_thread_count,
                                  uint8_t access_thread_count,
                                  uint8_t post_thread_count);
    void search_parallel_light_callback(
        SearchRequest&                  req,
        std::function<void(index_type)> post_callback,
        uint8_t                         thread_count);

    void insert(const UpdateRequest& req);

private:
    RockDBWrapper edb_;

    sse::crypto::TdpMultPool public_tdp_;
};

} // namespace sophos
} // namespace sse
