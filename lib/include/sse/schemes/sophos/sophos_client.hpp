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

#include <sse/schemes/sophos/sophos_common.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/prf.hpp>
#include <sse/crypto/tdp.hpp>

#include <array>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>

namespace sse {
namespace sophos {


class SophosClient
{
public:
    static constexpr size_t kKeywordIndexSize = 16;
    static constexpr size_t kKeySize          = 32;

    //    typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;

    //            static std::unique_ptr<SophosClient>
    //            construct_from_directory(const std::string& dir_path); static
    //            std::unique_ptr<SophosClient> init_in_directory(const
    //            std::string& dir_path, uint32_t n_keywords);

    //            SophosClient(const std::string& token_map_path);
    SophosClient(const std::string&      token_map_path,
                 const std::string&      tdp_private_key,
                 crypto::Key<kKeySize>&& derivation_master_key,
                 crypto::Key<kKeySize>&& rsa_prg_key);

    ~SophosClient();

    size_t keyword_count() const;

    std::string private_key() const;
    std::string public_key() const;

    //            void write_keys(const std::string& dir_path) const;

    SearchRequest search_request(const std::string& keyword) const;
    UpdateRequest insertion_request(const std::string& keyword,
                                    const index_type   index);

    const crypto::Prf<kDerivationKeySize>& derivation_prf() const;
    const sse::crypto::TdpInverse&         inverse_tdp() const;

    static const char* kTdpSkFile;
    static const char* kDerivationKeyFile;

private:
    static const char* kRsaPrgKeyFile;
    static const char* kCounterMapFile;

    crypto::Prf<kDerivationKeySize> k_prf_;
    sse::crypto::TdpInverse         inverse_tdp_;


    static std::string get_keyword_index(const std::string& kw);

    crypto::Prf<crypto::Tdp::kRSAPrfSize> rsa_prg_;

    sophos::RocksDBCounter counter_map_;
    std::mutex             token_map_mtx_;
};

} // namespace sophos
} // namespace sse
