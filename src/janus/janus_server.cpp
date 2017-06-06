//
//  janus_server.cpp
//  sophos
//
//  Created by Raphael Bost on 06/06/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include "janus_server.hpp"

namespace sse {
    namespace janus {
        
//        static inline std::string insertion_db_path(const std::string &path)
//        {
//            return path + "/insertion.db";
//        }
//        
//        static inline std::string deletion_db_path(const std::string &path)
//        {
//            return path + "/deletion.db";
//        }
        
        JanusServer::JanusServer(const std::string& db_add_path, const std::string& db_del_path) : insertion_server_(db_add_path), deletion_server_(db_del_path)
        {}

        
        
        
        std::list<index_type> JanusServer::search(const SearchRequest& req)
        {
            std::list<crypto::punct::ciphertext_type> insertions = insertion_server_.search(req.insertion_search_request);

            std::list<crypto::punct::key_share_type> key_shares = deletion_server_.search(req.deletion_search_request);
            
            
            key_shares.push_front(req.first_key_share);
            
            crypto::PuncturableDecryption decryptor(
                        crypto::punct::punctured_key_type{
                            std::make_move_iterator(std::begin(key_shares)),
                            std::make_move_iterator(std::end(key_shares)) }
                                                    );
            
            
            std::list<index_type> results;
            
            for (auto ct : insertions)
            {
                index_type r;
                if (decryptor.decrypt(ct, r)) {
                    results.push_back(r);
                }
            }
            
            
            return results;
        }
        
        
        
        void JanusServer::insert_entry(const InsertionRequest& req)
        {
            insertion_server_.update(req);
        }
        
        void JanusServer::delete_entry(const DeletionRequest& req)
        {
            deletion_server_.update(req);
        }

        std::ostream& JanusServer::print_stats(std::ostream& out) const
        {
            insertion_server_.print_stats(out);
            deletion_server_.print_stats(out);
            return out;
        }

        void JanusServer::flush_edb()
        {
            insertion_server_.flush_edb();
            deletion_server_.flush_edb();
        }


    }
}