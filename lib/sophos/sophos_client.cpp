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


#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/thread_pool.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <algorithm>
#include <iostream>

namespace sse {
namespace sophos {

const char* SophosClient::tdp_sk_file__         = "tdp_sk.key";
const char* SophosClient::derivation_key_file__ = "derivation_master.key";


const char* SophosClient::rsa_prg_key_file__ = "rsa_prg.key";
const char* SophosClient::counter_map_file__ = "counters.dat";

constexpr size_t SophosClient::kKeywordIndexSize;

SophosClient::SophosClient(const std::string&      token_map_path,
                           const std::string&      tdp_private_key,
                           crypto::Key<kKeySize>&& derivation_master_key,
                           crypto::Key<kKeySize>&& rsa_prg_key)
    : k_prf_(std::move(derivation_master_key)), inverse_tdp_(tdp_private_key),
      rsa_prg_(std::move(rsa_prg_key)), counter_map_(token_map_path)
{
}

SophosClient::~SophosClient() = default;

size_t SophosClient::keyword_count() const
{
    return counter_map_.approximate_size();
}

const std::string SophosClient::public_key() const
{
    return inverse_tdp_.public_key();
}

const std::string SophosClient::private_key() const
{
    return inverse_tdp_.private_key();
}

const crypto::Prf<kDerivationKeySize>& SophosClient::derivation_prf() const
{
    return k_prf_;
}
const sse::crypto::TdpInverse& SophosClient::inverse_tdp() const
{
    return inverse_tdp_;
}

std::string SophosClient::get_keyword_index(const std::string& kw) const
{
    std::string hash_string = crypto::Hash::hash(kw);
    return hash_string.erase(kKeywordIndexSize);
}

SearchRequest SophosClient::search_request(const std::string& keyword) const
{
    uint32_t      kw_counter;
    bool          found;
    SearchRequest req;
    req.add_count = 0;

    std::string seed = get_keyword_index(keyword);

    found = counter_map_.get(keyword, kw_counter);

    if (!found) {
        logger::log(logger::LoggerSeverity::INFO)
            << "No matching counter found for keyword " << keyword << " (index "
            << utility::hex_string(seed) << ")" << std::endl;
    } else {
        // Now derive the original search token from the kw_index (as seed)
        req.token = inverse_tdp().generate_array(rsa_prg_, seed);
        req.token = inverse_tdp().invert_mult(req.token, kw_counter);


        req.derivation_key = derivation_prf().prf(
            reinterpret_cast<const uint8_t*>(seed.data()), kKeywordIndexSize);
        req.add_count = kw_counter + 1;
    }

    return req;
}


UpdateRequest SophosClient::insertion_request(const std::string& keyword,
                                              const index_type   index)
{
    UpdateRequest     req;
    search_token_type st;

    // get (and possibly construct) the keyword index
    std::string seed = get_keyword_index(keyword);


    // retrieve the counter
    uint32_t kw_counter;

    bool success = counter_map_.get_and_increment(keyword, kw_counter);

    assert(success);

    st = inverse_tdp().generate_array(rsa_prg_, seed);

    if (kw_counter == 0) {
        logger::log(logger::LoggerSeverity::DBG)
            << "ST0 " << utility::hex_string(st) << std::endl;
    } else {
        st = inverse_tdp().invert_mult(st, kw_counter);

        if (logger::severity() <= logger::LoggerSeverity::DBG) {
            logger::log(logger::LoggerSeverity::DBG)
                << "New ST " << utility::hex_string(st) << std::endl;
        }
    }


    auto deriv_key = derivation_prf().prf(
        reinterpret_cast<const uint8_t*>(seed.data()), kKeywordIndexSize);

    if (logger::severity() <= logger::LoggerSeverity::DBG) {
        logger::log(logger::LoggerSeverity::DBG)
            << "Derivation key: " << utility::hex_string(deriv_key)
            << std::endl;
    }

    std::array<uint8_t, kUpdateTokenSize> mask;

    gen_update_token_masks(
        crypto::Prf<kUpdateTokenSize>(crypto::Key<kKeySize>(deriv_key.data())),
        st.data(),
        req.token,
        mask);
    req.index = utility::xor_mask(index, mask);

    if (logger::severity() <= logger::LoggerSeverity::DBG) {
        logger::log(logger::LoggerSeverity::DBG)
            << "Update token: (" << utility::hex_string(req.token) << ", "
            << std::hex << req.index << ")" << std::endl;
    }

    return req;
}
} // namespace sophos
} // namespace sse
