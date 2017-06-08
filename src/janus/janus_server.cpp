//
//  janus_server.cpp
//  sophos
//
//  Created by Raphael Bost on 06/06/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include "janus_server.hpp"

#include <set>

namespace sse {
    namespace sophos {
        
        using namespace janus;
        
        template<>
        struct serialization<JanusServer::cached_result_type>
        {
            std::string serialize(const JanusServer::cached_result_type& elt)
            {
                logger::log(logger::DBG) << "Serializing pair (" << hex_string(elt.first) << ", " << hex_string(elt.second) << ")\n";
                std::string out = std::string((char*)(&(elt.first)), sizeof(index_type)) + std::string(elt.second.begin(), elt.second.end());
                
                logger::log(logger::DBG) << "Serialized string: " << hex_string(out) << "\n";

                
                return out;
            }
            bool deserialize(std::string::iterator& begin, const std::string::iterator& end, JanusServer::cached_result_type& out)
            {

                if (end-begin < sizeof(janus::index_type)+sizeof(crypto::punct::kTagSize)) {
                    
                    if (end != begin) {
                        logger::log(logger::ERROR) << "Unable to deserialize" << std::endl;
                    }

                    return false;
                }
                logger::log(logger::DBG) << "Deserialized string: " << hex_string(std::string(begin, begin+sizeof(janus::index_type)+sizeof(crypto::punct::kTagSize))) << "\n";

                index_type ind;
                crypto::punct::tag_type tag;

                std::string tmp(begin, begin+sizeof(index_type));
                memcpy(&ind, tmp.data(), sizeof(index_type));
                
//                for (size_t i = 0; i < sizeof(index_type); i++) {
//                    // I wish it would have been prettier, but I couldn't find any way to do so ...
//                    // begin is not a char*, so no memcpy ...
//                    
//                    (&ind)[i] = *(begin+i);
//                }
                
                std::copy(begin+sizeof(index_type), begin+sizeof(index_type)+tag.size(), tag.begin());
                
                begin +=sizeof(index_type)+tag.size();
                
                out = std::make_pair(ind, std::move(tag));
                
                logger::log(logger::DBG) << "Deserializing pair (" << hex_string(out.first) << ", " << hex_string(out.second) << ")\n";

                return true;
            }
        };
 
    }
}
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
        
        JanusServer::JanusServer(const std::string& db_add_path, const std::string& db_del_path, const std::string& db_cache_path) :
            insertion_server_(db_add_path), deletion_server_(db_del_path), cached_results_edb_(db_cache_path)
        {}

        
        
        
        std::list<index_type> JanusServer::search(const SearchRequest& req)
        {
            std::list<crypto::punct::ciphertext_type> insertions = insertion_server_.search(req.insertion_search_request);

            std::list<crypto::punct::key_share_type> key_shares = deletion_server_.search(req.deletion_search_request);
            
            
            key_shares.push_front(req.first_key_share);
            
            // construct a set of newly removed tags
            std::set<crypto::punct::tag_type> removed_tags;
            for (auto sk : key_shares) {
                removed_tags.insert(crypto::punct::extract_tag(sk));
            }
            
            crypto::PuncturableDecryption decryptor(
                        crypto::punct::punctured_key_type{
                            std::make_move_iterator(std::begin(key_shares)),
                            std::make_move_iterator(std::end(key_shares)) }
                                                    );
            
            
            std::list<index_type> results;
            std::list<cached_result_type> cached_res_list;
            
            // get previously cached elements
            cached_results_edb_.get(req.keyword_token, cached_res_list);
            
            // filter the previously cached elements to remove newly removed entries
            auto it = cached_res_list.begin();
            
            while (it != cached_res_list.end()) {
                if(removed_tags.count(it->second) > 0)
                {
                    it = cached_res_list.erase(it);
                }else{
                    results.push_back(it->first);
                    ++it;
                }
            }
            
            
            for (auto ct : insertions)
            {
                index_type r;
                if (decryptor.decrypt(ct, r)) {
                    results.push_back(r);
                    cached_res_list.push_back(std::make_pair(r,crypto::punct::extract_tag(ct)));
                }
            }
            
            // store results in the cache
            cached_results_edb_.put(req.keyword_token, cached_res_list);
            
            
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
