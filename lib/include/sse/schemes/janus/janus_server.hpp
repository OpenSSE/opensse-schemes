//
//  janus_server.hpp
//  sophos
//
//  Created by Raphael Bost on 06/06/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include <sse/schemes/diana/diana_server.hpp>
#include <sse/schemes/janus/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/prf.hpp>

namespace sse {
namespace janus {


class JanusServer
{
public:
    using cached_result_type = std::pair<index_type, crypto::punct::tag_type>;

    JanusServer(const std::string& db_add_path,
                const std::string& db_del_path,
                const std::string& db_cache_path);

    bool get(const uint8_t* key, index_type& index) const;


    std::list<index_type> search(SearchRequest& req);
    std::list<index_type> search_parallel(SearchRequest& req,
                                          uint8_t        diana_threads_count);
    void                  search_parallel(SearchRequest& req,
                                          uint8_t        diana_threads_count,
                                          const std::function<void(index_type)>& post_callback);
    void                  search_parallel(
                         SearchRequest&                                  req,
                         uint8_t                                         diana_threads_count,
                         const std::function<void(index_type, uint8_t)>& post_callback);

    void insert(const InsertionRequest& req);
    void remove(const DeletionRequest& req);

    void flush_edb();

private:
    diana::DianaServer<crypto::punct::ciphertext_type> insertion_server_;
    diana::DianaServer<crypto::punct::key_share_type>  deletion_server_;

    sophos::RockDBListStore<cached_result_type> cached_results_edb_;
};

} // namespace janus
} // namespace sse
