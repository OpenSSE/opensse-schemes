//
//  janus_client.cpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include <sse/schemes/janus/janus_client.hpp>

namespace sse {
namespace janus {

inline std::string keyword_doc_string(const std::string& kw, index_type ind)
{
    return utility::hex_string(ind) + "||" + kw;
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::tag_derivation_key() const
{
    return master_prf_.derive_key("tag_derivation");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::punct_enc_key() const
{
    return master_prf_.derive_key("punct_enc");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::kw_token_key() const
{
    return master_prf_.derive_key("keyword_token");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::
    insertion_derivation_master_key() const
{
    return master_prf_.derive_key("add_derivation_master_key");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::
    insertion_kw_token_master_key() const
{
    return master_prf_.derive_key("add_kw_token_master_key");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::
    deletion_derivation_master_key() const
{
    return master_prf_.derive_key("del_derivation_master_key");
}

crypto::Key<JanusClient::kPRFKeySize> JanusClient::
    deletion_kw_token_master_key() const
{
    return master_prf_.derive_key("del_kw_token_master_key");
}


JanusClient::JanusClient(const std::string&         search_counter_map_path,
                         const std::string&         add_map_path,
                         const std::string&         del_map_path,
                         crypto::Key<kPRFKeySize>&& master_key)
    : master_prf_(std::move(master_key)), tag_prf_(tag_derivation_key()),
      punct_enc_master_prf_(punct_enc_key()), kw_token_prf_(kw_token_key()),
      insertion_client_(add_map_path,
                        insertion_derivation_master_key(),
                        insertion_kw_token_master_key()),
      deletion_client_(del_map_path,
                       deletion_derivation_master_key(),
                       deletion_kw_token_master_key()),
      search_counter_map_(search_counter_map_path)
{
}

std::string JanusClient::meta_keyword(const std::string& kw,
                                      uint32_t           search_counter)
{
    return utility::hex_string(search_counter) + kw;
}


SearchRequest JanusClient::search_request(const std::string& keyword)
{
    uint32_t search_counter = 0;
    if (!search_counter_map_.get(keyword, search_counter)) {
        search_counter = 0; // probably unnecessary but safer
    }

    std::string m_kw = meta_keyword(keyword, search_counter);


    keyword_token_type keyword_token = kw_token_prf_.prf(keyword);

    diana::SearchRequest insertion_search_request(
        insertion_client_.search_request(m_kw));
    diana::SearchRequest deletion_search_request(
        deletion_client_.search_request(
            m_kw, false)); // do not log if there is no deletion


    // the key derivation will to be modified for the real implementation
    crypto::PuncturableEncryption punct_encryption(
        punct_enc_master_prf_.derive_key(m_kw));
    crypto::punct::key_share_type first_key_share
        = punct_encryption.initial_keyshare(
            deletion_search_request
                .add_count); // the add_count for the deletion scheme is
                             // actually the number of deleted entries

    SearchRequest req(keyword_token,
                      std::move(insertion_search_request),
                      std::move(deletion_search_request),
                      first_key_share);
    // increment the search counter only if there were some insertions or some
    // deletions
    if (req.insertion_search_request.add_count > 0
        || req.deletion_search_request.add_count > 0) {
        search_counter_map_.set(keyword, search_counter + 1);
    }

    // cleanup the counter maps
    if (req.insertion_search_request.add_count > 0) {
        insertion_client_.remove_keyword(m_kw);
    }
    if (req.deletion_search_request.add_count > 0) {
        deletion_client_.remove_keyword(m_kw);
    }

    return req;
}

InsertionRequest JanusClient::insertion_request(const std::string& keyword,
                                                const index_type   index)
{
    uint32_t search_counter = 0;
    if (!search_counter_map_.get(keyword, search_counter)) {
        search_counter = 0; // probably unnecessary but safer
    }

    std::string m_kw = meta_keyword(keyword, search_counter);

    crypto::PuncturableEncryption punct_encryption(
        punct_enc_master_prf_.derive_key(m_kw));

    // use the real keyword to generate the tag
    crypto::punct::tag_type tag
        = tag_prf_.prf(keyword_doc_string(keyword, index));
    crypto::punct::ciphertext_type ct = punct_encryption.encrypt(index, tag);

    return insertion_client_.insertion_request(m_kw, ct);
}

DeletionRequest JanusClient::removal_request(const std::string& keyword,
                                             const index_type   index)
{
    uint32_t search_counter = 0;
    if (!search_counter_map_.get(keyword, search_counter)) {
        search_counter = 0; // probably unnecessary but safer
    }

    std::string m_kw = meta_keyword(keyword, search_counter);

    crypto::PuncturableEncryption punct_encryption(
        punct_enc_master_prf_.derive_key(m_kw));

    uint32_t n_del = deletion_client_.get_match_count(m_kw);

    // use the real keyword to generate the tag
    crypto::punct::tag_type tag
        = tag_prf_.prf(keyword_doc_string(keyword, index));
    crypto::punct::key_share_type ks
        = punct_encryption.inc_puncture(n_del + 1, tag);

    return deletion_client_.insertion_request(m_kw, ks);
}


} // namespace janus
} // namespace sse
