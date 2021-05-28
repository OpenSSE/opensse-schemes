//
//  janus_client.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include <sse/schemes/diana/diana_client.hpp>
#include <sse/schemes/janus/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
namespace janus {

class JanusClient
{
public:
    static constexpr size_t kPRFKeySize = 32;

    JanusClient(const std::string&         search_counter_map_path,
                const std::string&         add_map_path,
                const std::string&         del_map_path,
                crypto::Key<kPRFKeySize>&& master_key);

    static std::string meta_keyword(const std::string& kw,
                                    uint32_t           search_counter);

    SearchRequest    search_request(const std::string& keyword);
    InsertionRequest insertion_request(const std::string& keyword,
                                       const index_type   index);
    DeletionRequest  removal_request(const std::string& keyword,
                                     const index_type   index);

    //            std::list<UpdateRequest<T>>   bulk_insertion_request(const
    //            std::list<std::pair<std::string, index_type>> &update_list);
    //
    //
    //            //            SearchRequest   search_request_index(const
    //            keyword_index_type &kw_index) const;
    //            //            SearchRequest   random_search_request() const;
    //
    //
    //            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
    //            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
    //
    //            static const std::string derivation_keys_file__;
    //
    //            struct IndexHasher
    //            {
    //            public:
    //                inline size_t operator()(const keyword_index_type& index)
    //                const
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
    crypto::Key<JanusClient::kPRFKeySize> tag_derivation_key() const;
    crypto::Key<JanusClient::kPRFKeySize> punct_enc_key() const;
    crypto::Key<JanusClient::kPRFKeySize> kw_token_key() const;
    crypto::Key<JanusClient::kPRFKeySize> insertion_derivation_master_key()
        const;
    crypto::Key<JanusClient::kPRFKeySize> insertion_kw_token_master_key() const;
    crypto::Key<JanusClient::kPRFKeySize> deletion_derivation_master_key()
        const;
    crypto::Key<JanusClient::kPRFKeySize> deletion_kw_token_master_key() const;

    crypto::Prf<kPRFKeySize>                   master_prf_;
    crypto::Prf<crypto::punct::kTagSize>       tag_prf_;
    crypto::Prf<crypto::punct::kMasterKeySize> punct_enc_master_prf_;
    crypto::Prf<kKeywordTokenSize>             kw_token_prf_;

    diana::DianaClient<crypto::punct::ciphertext_type> insertion_client_;
    diana::DianaClient<crypto::punct::key_share_type>  deletion_client_;

    sophos::RocksDBCounter search_counter_map_;
};


} // namespace janus
} // namespace sse
