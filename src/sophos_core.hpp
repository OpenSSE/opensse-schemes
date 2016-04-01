//
//  sophos_core.hpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include <string>
#include <array>

#include <ssdmap/bucket_map.hpp>
#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
namespace sophos {
        

constexpr size_t kSearchTokenSize = noexcept(crypto::Tdp::message_size());
constexpr size_t kDerivationKeySize = 16;
constexpr size_t kUpdateTokenSize = 16;

//typedef std::array<uint8_t, kSearchTokenSize> search_token_type;
typedef std::string search_token_type;
typedef std::array<uint8_t, kUpdateTokenSize> update_token_type;
typedef uint64_t index_type;
    
struct TokenHasher
{
public:
    size_t operator()(const update_token_type& ut) const;
};
    
struct SearchRequest
{
    search_token_type   token;
    std::string         derivation_key;
    uint32_t            add_count;
};


struct UpdateRequest
{
    update_token_type   token;
    index_type          index;
};
    
    
class SophosClient {
public:
    SophosClient(const std::string& save_path);

    const std::string public_key() const;
    
    SearchRequest   search_request(const std::string &keyword) const;
    UpdateRequest   update_request(const std::string &keyword, const index_type index);
    
private:
    crypto::Prf<kDerivationKeySize> k_prf_;
    ssdmap::bucket_map< std::string, std::pair<search_token_type, uint32_t> > token_map_;
    sse::crypto::TdpInverse inverse_tdp_;
};

class SophosServer {
public:
    
    
    
    SophosServer(const std::string& db_path, const std::string& tdp_pk);
    
    std::list<index_type> search(const SearchRequest& req);
    void update(const UpdateRequest& req);
    
private:
    ssdmap::bucket_map<update_token_type, index_type, TokenHasher> edb_;
    
    sse::crypto::Tdp public_tdp_;
};

} // namespace sophos
} // namespace sse
