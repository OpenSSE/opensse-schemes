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

#include <sse/crypto/prf.hpp>

#include <ssdmap/bucket_map.hpp>

namespace sse {
    namespace diane {
        
        class DianeClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;

            static constexpr size_t kTreeDepth = 48;
            
            DianeClient(const std::string& token_map_path, const size_t tm_setup_size);
            DianeClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key);
            ~DianeClient();

            size_t keyword_count() const;
            
            const std::string master_derivation_key() const;
            const std::string kw_token_master_key() const;
            
            keyword_index_type get_keyword_index(const std::string &kw) const;

            SearchRequest   search_request(const std::string &keyword) const;
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            

            SearchRequest   search_request_index(const keyword_index_type &kw_index) const;
            SearchRequest   random_search_request() const;

            std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
            
            static const std::string derivation_keys_file__;
            
            struct IndexHasher
            {
            public:
                inline size_t operator()(const keyword_index_type& index) const
                {
                    size_t h = 0;
                    for (size_t i = 0; i < index.size(); i++) {
                        if (i > 0) {
                            h <<= 8;
                        }
                        h = index[i] + h;
                    }
                    return h;
                }

            };

        private:

            crypto::Prf<kSearchTokenKeySize> root_prf_;
            crypto::Prf<kKeywordTokenSize> kw_token_prf_;
            
            
            ssdmap::bucket_map< keyword_index_type, uint32_t, IndexHasher> counter_map_;
            std::mutex token_map_mtx_;
            std::atomic_uint keyword_counter_;
        };
        
        

    }
}