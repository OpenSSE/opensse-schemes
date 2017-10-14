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

#include "sophos_common.hpp"
#include "utils/rocksdb_wrapper.hpp"

#include <string>
#include <array>
#include <fstream>
#include <functional>
#include <mutex>

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
    namespace sophos {
        
        
        
        class SophosClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            //    typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;
            
            static std::unique_ptr<SophosClient> construct_from_directory(const std::string& dir_path);
            static std::unique_ptr<SophosClient> init_in_directory(const std::string& dir_path, uint32_t n_keywords);
            
            SophosClient(const std::string& token_map_path, const size_t tm_setup_size);
            SophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key);
            SophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size);
            
            ~SophosClient();
            
            size_t keyword_count() const;
            
            const std::string private_key() const;
            const std::string public_key() const;
            const std::string master_derivation_key() const;
            std::string rsa_prg_key() const;
            
            void write_keys(const std::string& dir_path) const;
            
            SearchRequest   search_request(const std::string &keyword) const;
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            
            std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kDerivationKeySize>& derivation_prf() const;
            const sse::crypto::TdpInverse& inverse_tdp() const;
            
            static const std::string tdp_sk_file__;
            static const std::string derivation_key_file__;
            
        private:
            static const std::string rsa_prg_key_file__;
            static const std::string counter_map_file__;
            
            crypto::Prf<kDerivationKeySize> k_prf_;
            sse::crypto::TdpInverse inverse_tdp_;
            
            
            std::string get_keyword_index(const std::string &kw) const;
            
            crypto::Prf<crypto::Tdp::kRSAPrgSize> rsa_prg_;
            
            sophos::RocksDBCounter counter_map_;
            std::mutex token_map_mtx_;
            
        };
    } // namespace sophos
} // namespace sse
