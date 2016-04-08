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
#include <fstream>

#include <ssdmap/bucket_map.hpp>
#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
namespace sophos {
        

constexpr size_t kSearchTokenSize = crypto::Tdp::kMessageSize;
constexpr size_t kDerivationKeySize = 16;
constexpr size_t kUpdateTokenSize = 16;

typedef std::array<uint8_t, kSearchTokenSize> search_token_type;
//typedef std::string search_token_type;
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
    SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size);
    SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key);
    ~SophosClient();
    
    size_t keyword_count() const;
    
    const std::string private_key() const;
    const std::string public_key() const;
    
    const std::string master_derivation_key() const;

    SearchRequest   search_request(const std::string &keyword) const;
    UpdateRequest   update_request(const std::string &keyword, const index_type index);
    
    
    std::ostream& db_to_json(std::ostream& out) const;
    
private:
    void load_keyword_indices(const std::string &path);
    
    crypto::Prf<kDerivationKeySize> k_prf_;
    ssdmap::bucket_map< uint32_t, std::pair<search_token_type, uint32_t> > token_map_;
    std::map<std::string, uint32_t> keyword_indices_;
    
    std::ofstream keyword_indexer_stream_;
    
    sse::crypto::TdpInverse inverse_tdp_;
    
    std::mutex kw_index_mtx_;
    std::mutex token_map_mtx_;
    std::atomic_uint keyword_counter_;
};

class SophosServer {
public:
    
    
    
    SophosServer(const std::string& db_path, const std::string& tdp_pk);
    SophosServer(const std::string& db_path, const size_t tm_setup_size, const std::string& tdp_pk);
    
    const std::string public_key() const;

    std::list<index_type> search(const SearchRequest& req);
    void update(const UpdateRequest& req);
    
private:
    ssdmap::bucket_map<update_token_type, index_type, TokenHasher> edb_;
    
    sse::crypto::Tdp public_tdp_;
};

} // namespace sophos
} // namespace sse
