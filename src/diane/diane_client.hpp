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
            DianeClient();
            DianeClient(const std::string& derivation_master_key);
            ~DianeClient();

            size_t keyword_count() const;
            
            const std::string master_derivation_key() const;
            
            void write_keys(const std::string& dir_path) const;


            SearchRequest   search_request(const std::string &keyword) const;
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            
            virtual std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
            
            static const std::string derivation_keys_file__;
            
        private:
            crypto::Prf<kSearchTokenKeySize> root_prf_;
            crypto::Prf<kKeywordTokenSize> kw_token_prf_;
        };
        
        

    }
}