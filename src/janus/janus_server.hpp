//
//  janus_server.hpp
//  sophos
//
//  Created by Raphael Bost on 06/06/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include "types.hpp"

#include "diana/diana_server.hpp"
#include "utils/rocksdb_wrapper.hpp"

#include <sse/crypto/prf.hpp>

namespace sse {
    namespace janus {
        
        
        class JanusServer {
        public:
            typedef std::pair<index_type, crypto::punct::tag_type> cached_result_type;
            
            JanusServer(const std::string& db_add_path, const std::string& db_del_path, const std::string& db_cache_path);
            
            bool get(const uint8_t *key, index_type &index) const;
            
            
            std::list<index_type> search(const SearchRequest& req);
            std::list<index_type> search_parallel(const SearchRequest& req, uint8_t threads_count);
            void search_parallel(const SearchRequest& req, uint8_t threads_count, const std::function<void(index_type)> &post_callback);
            void search_parallel(const SearchRequest& req, uint8_t threads_count, const std::function<void(index_type, uint8_t)> &post_callback);
            
//            void search(const SearchRequest& req, const std::function<void(index_type)> &post_callback);
//            void search_simple(const SearchRequest& req, const std::function<void(index_type)> &post_callback);
//            
//            std::list<index_type> search_parallel(const SearchRequest& req, uint8_t derivation_threads_count,uint8_t access_threads_count);
//            void search_parallel(const SearchRequest& req, const std::function<void(index_type)> &post_callback, uint8_t derivation_threads_count,uint8_t access_threads_count);
//            
//            std::list<index_type> search_simple_parallel(const SearchRequest& req, uint8_t threads_count);
//            void search_simple_parallel(const SearchRequest& req, uint8_t threads_count, std::vector<index_type> &results);
//            void search_simple_parallel(const SearchRequest& req, const std::function<void(index_type)> &post_callback, uint8_t threads_count);
//            void search_simple_parallel(const SearchRequest& req, const std::function<void(index_type, uint8_t)> &post_callback, uint8_t threads_count);
//            
            
            void insert_entry(const InsertionRequest& req);
            void delete_entry(const DeletionRequest& req);
            
            std::ostream& print_stats(std::ostream& out) const;
            
            void flush_edb();
        private:
            diana::DianaServer<crypto::punct::ciphertext_type> insertion_server_;
            diana::DianaServer<crypto::punct::key_share_type> deletion_server_;

            sophos::RockDBListStore<cached_result_type> cached_results_edb_;

        };
        
    }
}
