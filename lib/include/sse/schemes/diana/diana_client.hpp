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

#include <sse/schemes/diana/diana_common.hpp>
#include <sse/schemes/diana/types.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>
#include <sse/crypto/rcprf.hpp>
#include <sse/crypto/wrapper.hpp>
#include <sse/dbparser/json/rapidjson/document.h>
#include <sse/dbparser/json/rapidjson/filereadstream.h>
#include <sse/dbparser/json/rapidjson/filewritestream.h>
#include <sse/dbparser/json/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/json/rapidjson/prettywriter.h>
#include <sse/dbparser/json/rapidjson/rapidjson.h>
#include <sse/dbparser/json/rapidjson/writer.h>

namespace sse {
namespace diana {

template<typename T>
class DianaClient
{
public:
    static constexpr size_t kKeywordIndexSize = 16;
    static constexpr size_t kKeySize          = 32;

    using keyword_index_type = std::array<uint8_t, kKeywordIndexSize>;
    using index_type         = T;

    static constexpr size_t kTreeDepth = 48;

    // issue with cppcheck on Xenial
    // cppcheck-suppress noExplicitConstructor
    DianaClient(const std::string&      token_map_path,
                crypto::Key<kKeySize>&& derivation_master_key,
                crypto::Key<kKeySize>&& kw_token_master_key);
    ~DianaClient();

    size_t keyword_count() const;

    keyword_index_type get_keyword_index(const std::string& kw) const;

    uint32_t get_match_count(const std::string& kw) const;

    SearchRequest               search_request(const std::string& keyword,
                                               bool               log_not_found = true) const;
    UpdateRequest<T>            insertion_request(const std::string& keyword,
                                                  const index_type   index);
    std::list<UpdateRequest<T>> bulk_insertion_request(
        const std::list<std::pair<std::string, index_type>>& update_list);

    bool remove_keyword(const std::string& kw);

    const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
    const crypto::Prf<kKeywordTokenSize>&   kw_token_prf() const;

private:
    std::list<std::tuple<std::string, T, uint32_t>> get_counters_and_increment(
        const std::list<std::pair<std::string, index_type>>& update_list);

    crypto::Prf<kSearchTokenKeySize> root_prf_;
    crypto::Prf<kKeywordTokenSize>   kw_token_prf_;

    sophos::RocksDBCounter counter_map_;
};

} // namespace diana
} // namespace sse

namespace sse {
namespace diana {

template<typename T>
DianaClient<T>::DianaClient(const std::string&      token_map_path,
                            crypto::Key<kKeySize>&& derivation_master_key,
                            crypto::Key<kKeySize>&& kw_token_master_key)
    : root_prf_(std::move(derivation_master_key)),
      kw_token_prf_(std::move(kw_token_master_key)),
      counter_map_(token_map_path)
{
}

template<typename T>
DianaClient<T>::~DianaClient() = default;

template<typename T>
typename DianaClient<T>::keyword_index_type DianaClient<T>::get_keyword_index(
    const std::string& kw) const
{
    std::string hash_string = crypto::Hash::hash(kw);

    keyword_index_type ret;
    std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());

    return ret;
}

template<typename T>
uint32_t DianaClient<T>::get_match_count(const std::string& kw) const
{
    uint32_t kw_counter;

    bool found = counter_map_.get(kw, kw_counter);

    return (found) ? kw_counter : 0;
}

template<typename T>
SearchRequest DianaClient<T>::search_request(const std::string& keyword,
                                             bool log_not_found) const
{
    keyword_index_type kw_index = get_keyword_index(keyword);

    bool     found;
    uint32_t kw_counter;
    // SearchRequest req;

    found = counter_map_.get(keyword, kw_counter);

    if (!found) {
        if (log_not_found) {
            logger::logger()->info("No matching counter found for keyword "
                                   + utility::hex_string(std::string(
                                       kw_index.begin(), kw_index.end())));
        }
        return SearchRequest(
            {{}}, crypto::ConstrainedRCPrf<kSearchTokenKeySize>({}), 0);
    }
    // else {
    uint32_t add_count = kw_counter + 1;

    // Compute the root of the tree attached to kw_index
    crypto::RCPrf<kKeySize> rcprf_root(
        root_prf_.derive_key(kw_index.data(), kw_index.size()), kTreeDepth);

    return SearchRequest(kw_token_prf_.prf(kw_index),
                         rcprf_root.constrain(0, kw_counter)
                         /*std::move(constrained_rcprf)*/,
                         add_count);
}

template<typename T>
UpdateRequest<T> DianaClient<T>::insertion_request(const std::string& keyword,
                                                   const index_type   index)
{
    UpdateRequest<T>      req;
    search_token_key_type st;
    index_type            mask;

    // get (and possibly construct) the keyword index
    keyword_index_type kw_index = get_keyword_index(keyword);

    // retrieve the counter
    uint32_t kw_counter;

    bool success = counter_map_.get_and_increment(keyword, kw_counter);

    if (!success) {
        throw std::runtime_error(
            "Unable to increment the keyword counter for keyword \"" + keyword
            + "\"");
    }

    sse::crypto::RCPrf<kKeySize> rcprf_root(
        root_prf_.derive_key(kw_index.data(), kw_index.size()), kTreeDepth);

    st = rcprf_root.eval(kw_counter);

    // TokenTree::inner_token_type root
    //     = root_prf_.derive_key(kw_index.data(), kw_index.size());

    // st = TokenTree::derive_node(std::move(root), kw_counter, kTreeDepth);

    logger::logger()->debug("New Search Token " + utility::hex_string(st));

    gen_update_token_mask(st, req.token, mask);

    req.index = xor_mask(index, mask);

    logger::logger()->debug("Update Request: (" + utility::hex_string(req.token)
                            + ", " + utility::hex_string(req.index) + ")");
    return req;
}

template<typename T>
std::list<UpdateRequest<T>> DianaClient<T>::bulk_insertion_request(
    const std::list<std::pair<std::string, index_type>>& update_list)
{
    std::list<UpdateRequest<T>> req_list;

    std::list<std::tuple<std::string, T, uint32_t>> counter_list
        = get_counters_and_increment(update_list);

    for (auto it = counter_list.begin(); it != counter_list.end(); ++it) {
        std::string           keyword = std::get<0>(*it);
        index_type            index   = std::get<1>(*it);
        UpdateRequest<T>      req;
        search_token_key_type st;
        index_type            mask;

        // get (and possibly construct) the keyword index
        keyword_index_type kw_index = get_keyword_index(keyword);

        // retrieve the counter
        uint32_t kw_counter = std::get<2>(*it);

        sse::crypto::RCPrf<kKeySize> rcprf_root(
            root_prf_.derive_key(kw_index.data(), kw_index.size()), kTreeDepth);

        st = rcprf_root.eval(kw_counter);

        // TokenTree::inner_token_type root
        //     = root_prf_.derive_key(kw_index.data(), kw_index.size());

        // st = TokenTree::derive_node(std::move(root), kw_counter, kTreeDepth);

        logger::logger()->debug("New Search Token " + utility::hex_string(st));

        gen_update_token_mask(st, req.token, mask);

        req.index = xor_mask(index, mask);

        req_list.push_back(req);
    }

    return req_list;
}

template<typename T>
std::list<std::tuple<std::string, T, uint32_t>> DianaClient<T>::
    get_counters_and_increment(
        const std::list<std::pair<std::string, index_type>>& update_list)
{
    std::list<std::tuple<std::string, index_type, uint32_t>> res;

    for (auto it = update_list.begin(); it != update_list.end(); ++it) {
        std::string keyword = it->first;
        index_type  index   = it->second;

        // retrieve the counter
        uint32_t kw_counter;
        bool     success = counter_map_.get_and_increment(keyword, kw_counter);

        if (!success) {
            throw std::runtime_error(
                "Unable to increment the keyword counter for keyword \""
                + keyword + "\"");
        }

        res.push_back(std::make_tuple(keyword, index, kw_counter));
    }

    return res;
}

template<typename T>
bool DianaClient<T>::remove_keyword(const std::string& kw)
{
    return counter_map_.remove_key(kw);
}

template<typename T>
size_t DianaClient<T>::keyword_count() const
{
    return counter_map_.approximate_size();
}

} // namespace diana
} // namespace sse
