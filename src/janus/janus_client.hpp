//
//  janus_client.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include "types.hpp"

#include "diane/diane_client.hpp"

#include <sse/crypto/prf.hpp>

namespace sse {
    namespace janus {
        
        class JanusClient {
        public:
            JanusClient(const std::string& add_map_path, const std::string& del_map_path);
            JanusClient(const std::string& add_map_path, const std::string& del_map_path, const std::string& tag_derivation_key, const std::string& punct_enc_derivation_key);
//            ~JanusClient();
            
            
            inline const std::string tag_derivation_key() const
            {
                return std::string(tag_prf_.key().begin(), tag_prf_.key().end());
            }
            
            SearchRequest       search_request(const std::string &keyword) const;
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
            
//            std::list<std::tuple<std::string, T, uint32_t>>   get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list);
            
//            crypto::Prf<kSearchTokenKeySize> root_prf_;
            crypto::Prf<crypto::punct::kTagSize> tag_prf_;
            crypto::Prf<crypto::punct::kMasterKeySize> punct_enc_master_prf_;
            
            diane::DianeClient<crypto::punct::ciphertext_type> insertion_client_;
            diane::DianeClient<crypto::punct::key_share_type> deletion_client_;
            
//            sophos::RocksDBCounter counter_map_;
//            std::atomic_uint keyword_counter_;
        };
        
        
        
    }
}
