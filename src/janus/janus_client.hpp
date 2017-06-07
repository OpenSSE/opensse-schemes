//
//  janus_client.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include <sse/crypto/prf.hpp>

#include "types.hpp"
#include "diane/diane_client.hpp"
#include "utils/rocksdb_wrapper.hpp"

namespace sse {
    namespace janus {
        
        class JanusClient {
        public:
            
            static constexpr size_t kSubkeysSize = 32;
            
            JanusClient(const std::string& search_counter_map_path, const std::string& add_map_path, const std::string& del_map_path);
            JanusClient(const std::string& search_counter_map_path, const std::string& add_map_path, const std::string& del_map_path, const std::string& master_key);
//            ~JanusClient();
            
            
            inline const std::string master_key() const
            {
                return std::string(master_prf_.key().begin(), master_prf_.key().end());
            }

            std::string meta_keyword(const std::string &kw, uint32_t search_counter) const;
            
            SearchRequest       search_request(const std::string &keyword);
            InsertionRequest    insertion_request(const std::string &keyword, const index_type index);
            DeletionRequest     deletion_request(const std::string &keyword, const index_type index);

            //            std::list<UpdateRequest<T>>   bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list);
//            
//            
//            //            SearchRequest   search_request_index(const keyword_index_type &kw_index) const;
//            //            SearchRequest   random_search_request() const;
//            
//            std::ostream& print_stats(std::ostream& out) const;
//            
//            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
//            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
//            
//            static const std::string derivation_keys_file__;
//            
//            struct IndexHasher
//            {
//            public:
//                inline size_t operator()(const keyword_index_type& index) const
//                {
//                    size_t h = 0;
//                    for (size_t i = 0; i < index.size(); i++) {
//                        if (i > 0) {
//                            h <<= 8;
//                        }
//                        h = index[i] + h;
//                    }
//                    return h;
//                }
//                
//            };
            
        private:
            
            std::string tag_derivation_key() const;
            std::string punct_enc_key() const;
            std::string kw_token_key() const;
            std::string insertion_derivation_master_key() const;
            std::string insertion_kw_token_master_key() const;
            std::string deletion_derivation_master_key() const;
            std::string delertion_kw_token_master_key() const;
            
            crypto::Prf<kSubkeysSize> master_prf_;
            crypto::Prf<crypto::punct::kTagSize> tag_prf_;
            crypto::Prf<crypto::punct::kMasterKeySize> punct_enc_master_prf_;
            crypto::Prf<kKeywordTokenSize> kw_token_prf_;

            diane::DianeClient<crypto::punct::ciphertext_type> insertion_client_;
            diane::DianeClient<crypto::punct::key_share_type> deletion_client_;
            
            sophos::RocksDBCounter search_counter_map_;
            
        };
        
        
        
    }
}
