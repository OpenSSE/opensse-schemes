//
//  large_storage_sophos_client.hpp
//  sophos
//
//  Created by Raphael Bost on 13/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include "sophos_core.hpp"

namespace sse {
    namespace sophos {
        
        class MediumStorageSophosClient : public SophosClient {
        public:
            static std::unique_ptr<SophosClient> construct_from_json(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& json_path);
            
            MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size);
            MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key);
            MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size);
            ~MediumStorageSophosClient();
            
            size_t keyword_count() const;
            
            SearchRequest   search_request(const std::string &keyword) const;
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            
            std::string rsa_prg_key() const;
            
            std::ostream& db_to_json(std::ostream& out) const;
            std::ostream& print_stats(std::ostream& out) const;
            
        private:
            class JSONHandler;
            friend JSONHandler;
            
            void load_keyword_indices(const std::string &path);
            
            int64_t find_keyword_index(const std::string &kw) const;
            uint32_t get_keyword_index(const std::string &kw);
            uint32_t get_keyword_index(const std::string &kw, bool& is_new);
            uint32_t new_keyword_index(const std::string &kw);
            
            crypto::Prf<crypto::Tdp::kRSAPrgSize> rsa_prg_;
            
            ssdmap::bucket_map< uint32_t, uint32_t > counter_map_;
            std::map<std::string, uint32_t> keyword_indices_;
            
            std::ofstream keyword_indexer_stream_;
            
            std::mutex kw_index_mtx_;
            std::mutex token_map_mtx_;
            std::atomic_uint keyword_counter_;
        };
        
    }
}