//
//  large_storage_sophos_client.hpp
//  sophos
//
//  Created by Raphael Bost on 13/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include "sophos_core.hpp"

#include <mutex>
#include <atomic>
#include <memory>

namespace sse {
namespace sophos {

class LargeStorageSophosClient : public SophosClient {
public:
    static std::unique_ptr<SophosClient> construct_from_directory(const std::string& dir_path);
    static std::unique_ptr<SophosClient> init_in_directory(const std::string& dir_path, uint32_t n_keywords);

    static std::unique_ptr<SophosClient> construct_from_json(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& json_path);
    
    LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size);
    LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key);
    LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const size_t tm_setup_size);
    ~LargeStorageSophosClient();
    
    size_t keyword_count() const;
    
    SearchRequest   search_request(const std::string &keyword) const;
    UpdateRequest   update_request(const std::string &keyword, const index_type index);
    
    
    std::ostream& db_to_json(std::ostream& out) const;
    std::ostream& print_stats(std::ostream& out) const;

    static const std::string token_map_file__;
    static const std::string keyword_counter_file__;

private:
    class JSONHandler;
    friend JSONHandler;
    
    void load_keyword_indices(const std::string &path);
    
    int64_t find_keyword_index(const std::string &kw) const;
    uint32_t get_keyword_index(const std::string &kw);
    uint32_t get_keyword_index(const std::string &kw, bool& is_new);
    uint32_t new_keyword_index(const std::string &kw);
    
    ssdmap::bucket_map< uint32_t, std::pair<search_token_type, uint32_t> > token_map_;
    std::map<std::string, uint32_t> keyword_indices_;
    
    std::ofstream keyword_indexer_stream_;
    
    std::mutex kw_index_mtx_;
    std::mutex token_map_mtx_;
    std::atomic_uint keyword_counter_;
};

}
}