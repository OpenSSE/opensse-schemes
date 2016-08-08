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

#include "token_tree.hpp"
#include "types.hpp"

#include "utils/rocksdb_wrapper.hpp"


#include <sse/crypto/prf.hpp>

#include <ssdmap/bucket_map.hpp>

namespace sse {
    namespace diane {
        
        

class DianeServer {
public:
    
    
    
    DianeServer(const std::string& db_path);
    DianeServer(const std::string& db_path, const size_t tm_setup_size);
    
    bool get(const uint8_t *key, index_type &index) const;


    std::list<index_type> search(const SearchRequest& req);
    void search(const SearchRequest& req, const std::function<void(index_type)> &post_callback);
    void search_simple(const SearchRequest& req, const std::function<void(index_type)> &post_callback);
    
    std::list<index_type> search_parallel(const SearchRequest& req, uint8_t derivation_threads_count,uint8_t access_threads_count);
    void search_parallel(const SearchRequest& req, const std::function<void(index_type)> &post_callback, uint8_t derivation_threads_count,uint8_t access_threads_count);

    std::list<index_type> search_simple_parallel(const SearchRequest& req, uint8_t threads_count);
    void search_simple_parallel(const SearchRequest& req, uint8_t threads_count, std::vector<index_type> &results);
    void search_simple_parallel(const SearchRequest& req, const std::function<void(index_type)> &post_callback, uint8_t threads_count);
    void search_simple_parallel(const SearchRequest& req, const std::function<void(index_type, uint8_t)> &post_callback, uint8_t threads_count);

    
    void update(const UpdateRequest& req);
    
    std::ostream& print_stats(std::ostream& out) const;
    
    void flush_edb();
private:

    sophos::RockDBWrapper edb_;
    
};
        
    }
}
