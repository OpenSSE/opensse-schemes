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

#include "sophos_core.hpp"

#include <array>
#include <mutex>
#include <memory>
#include <atomic>

namespace sse {
    namespace sophos {
        
        class MediumStorageSophosClient : public SophosClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;
            
            static std::unique_ptr<SophosClient> construct_from_directory(const std::string& dir_path);
            static std::unique_ptr<SophosClient> init_in_directory(const std::string& dir_path, uint32_t n_keywords);

            
            static std::unique_ptr<SophosClient> construct_from_json(const std::string& dir_path, const std::string& json_path);
            
            MediumStorageSophosClient(const std::string& token_map_path, const size_t tm_setup_size);
            MediumStorageSophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key);
            MediumStorageSophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size);
            ~MediumStorageSophosClient();
            
            size_t keyword_count() const;
            
            SearchRequest   search_request(const std::string &keyword) const;
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            
            SearchRequest   random_search_request() const;

            
            std::string rsa_prg_key() const;
            
            void write_keys(const std::string& dir_path) const;
            
            std::ostream& db_to_json(std::ostream& out) const;
            std::ostream& print_stats(std::ostream& out) const;
            
            struct IndexHasher
            {
            public:
                size_t operator()(const keyword_index_type& ind) const;
            };

        private:
            static const std::string rsa_prg_key_file__;
            static const std::string counter_map_file__;

            class JSONHandler;
            friend JSONHandler;
            
            keyword_index_type get_keyword_index(const std::string &kw) const;
            
            crypto::Prf<crypto::Tdp::kRSAPrgSize> rsa_prg_;
            
            ssdmap::bucket_map< keyword_index_type, uint32_t, IndexHasher> counter_map_;
            std::mutex token_map_mtx_;
            std::atomic_uint keyword_counter_;
        };
    }
}