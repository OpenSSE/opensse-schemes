//
//  janus_server.cpp
//  sophos
//
//  Created by Raphael Bost on 06/06/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include <sse/schemes/janus/janus_server.hpp>

#include <set>

namespace sse {
namespace sophos {

template<>
struct serialization<janus::JanusServer::cached_result_type>
{
    std::string serialize(const janus::JanusServer::cached_result_type& elt)
    {
        logger::logger()->debug("Serializing pair ("
                                + utility::hex_string(elt.first) + ", "
                                + utility::hex_string(elt.second) + ")");

        return std::string(reinterpret_cast<const char*>(&(elt.first)),
                           sizeof(janus::index_type))
               + std::string(elt.second.begin(), elt.second.end());
        ;
    }
    bool deserialize(std::string::iterator&                  begin,
                     const std::string::iterator&            end,
                     janus::JanusServer::cached_result_type& out)
    {
        if (end < begin + sizeof(janus::index_type)
                      + sizeof(crypto::punct::kTagSize)) {
            if (end != begin) {
                logger::logger()->error("Error when deserializing");
            }

            return false;
        }
        logger::logger()->debug("Deserialized string: "
                                + utility::hex_string(std::string(
                                    begin,
                                    begin + sizeof(janus::index_type)
                                        + sizeof(crypto::punct::kTagSize))));

        janus::index_type       ind;
        crypto::punct::tag_type tag;

        std::copy(begin,
                  begin + sizeof(janus::index_type),
                  reinterpret_cast<uint8_t*>(&ind));
        std::copy(begin + sizeof(janus::index_type),
                  begin + sizeof(janus::index_type) + tag.size(),
                  tag.begin());

        begin += sizeof(janus::index_type) + tag.size();

        out = std::make_pair(ind, tag);

        logger::logger()->debug("Deserializing pair ("
                                + utility::hex_string(out.first) + ", "
                                + utility::hex_string(out.second) + ")");

        return true;
    }
};

} // namespace sophos
} // namespace sse
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

JanusServer::JanusServer(const std::string& db_add_path,
                         const std::string& db_del_path,
                         const std::string& db_cache_path)
    : insertion_server_(db_add_path), deletion_server_(db_del_path),
      cached_results_edb_(db_cache_path)
{
}


std::list<index_type> JanusServer::search(SearchRequest& req)
{
    std::list<crypto::punct::ciphertext_type> insertions
        = insertion_server_.search(req.insertion_search_request, true);

    std::list<crypto::punct::key_share_type> key_shares
        = deletion_server_.search(req.deletion_search_request, true);

    // std::list<crypto::punct::ciphertext_type> insertions
    //     = insertion_server_.search_parallel(
    //         req.insertion_search_request, 8, true);

    // std::list<crypto::punct::key_share_type> key_shares
    //     = deletion_server_.search_parallel(
    //         req.deletion_search_request, 8, true);

    key_shares.push_front(req.first_key_share);

    // construct a set of newly removed tags
    std::set<crypto::punct::tag_type> removed_tags;
    auto                              sk_it = key_shares.begin();
    ++sk_it; // skip the first element
    for (; sk_it != key_shares.end(); ++sk_it) {
        auto tag = crypto::punct::extract_tag(*sk_it);
        logger::logger()->debug("Tag " + utility::hex_string(tag) + " removed");
        removed_tags.insert(tag);
    }

    crypto::PuncturableDecryption decryptor(crypto::punct::punctured_key_type{
        std::make_move_iterator(std::begin(key_shares)),
        std::make_move_iterator(std::end(key_shares))});


    std::list<index_type>         results;
    std::list<cached_result_type> cached_res_list;

    // get previously cached elements
    cached_results_edb_.get(req.keyword_token, cached_res_list);


    // filter the previously cached elements to remove newly removed entries
    auto it = cached_res_list.begin();

    while (it != cached_res_list.end()) {
        if (removed_tags.count(it->second) > 0) {
            it = cached_res_list.erase(it);
        } else {
            results.push_back(it->first);
            ++it;
        }
    }


    for (auto ct : insertions) {
        index_type r;
        if (decryptor.decrypt(ct, r)) {
            results.push_back(r);
            cached_res_list.emplace_back(r, crypto::punct::extract_tag(ct));
        }
    }

    // store results in the cache
    cached_results_edb_.put(req.keyword_token, cached_res_list);


    return results;
}

std::list<index_type> JanusServer::search_parallel(SearchRequest& req,
                                                   uint8_t diana_threads_count)
{
    // use one result list per thread so to avoid using locks
    std::vector<std::list<index_type>> result_lists(diana_threads_count + 1);

    auto callback = [&result_lists](index_type i, uint8_t thread_id) {
        result_lists[thread_id].push_back(i);
    };

    search_parallel(req, diana_threads_count, callback);

    // merge the result lists
    std::list<index_type> results(std::move(result_lists[0]));
    for (size_t i = 1; i < result_lists.size(); i++) {
        results.splice(results.end(), result_lists[i]);
    }

    return results;
}

void JanusServer::search_parallel(
    SearchRequest&                         req,
    uint8_t                                diana_threads_count,
    const std::function<void(index_type)>& post_callback)
{
    auto aux = [&post_callback](index_type ind, uint8_t /*i*/) {
        post_callback(ind);
    };
    search_parallel(req, diana_threads_count, aux);
}

void JanusServer::search_parallel(
    SearchRequest&                                  req,
    uint8_t                                         diana_threads_count,
    const std::function<void(index_type, uint8_t)>& post_callback)
{
    // start by retrieving the key shares
    std::list<crypto::punct::key_share_type> key_shares
        = deletion_server_.search_parallel(
            req.deletion_search_request, diana_threads_count, true);

    key_shares.push_front(req.first_key_share);


    crypto::PuncturableDecryption decryptor(crypto::punct::punctured_key_type{
        std::make_move_iterator(std::begin(key_shares)),
        std::make_move_iterator(std::end(key_shares))});

    std::list<cached_result_type> new_cache;
    std::list<cached_result_type> filtered_cache;
    std::mutex                    cache_mtx;

    auto decryption_callback
        = [&decryptor, &post_callback, &new_cache, &cache_mtx](
              crypto::punct::ciphertext_type ct, uint8_t i) {
              index_type r;
              if (decryptor.decrypt(ct, r)) {
                  post_callback(r, i);

                  cache_mtx.lock();
                  new_cache.emplace_back(r, crypto::punct::extract_tag(ct));
                  cache_mtx.unlock();
              }
          };

    auto decryption_callback_unique
        = [&decryption_callback](crypto::punct::ciphertext_type ct) {
              decryption_callback(ct, 0);
          };

    // this job will be used to retrieve cached results and filter them
    auto cached_res_job = [this,
                           &req,
                           &key_shares,
                           &post_callback,
                           &diana_threads_count,
                           &filtered_cache]() {
        // construct a set of newly removed tags
        std::set<crypto::punct::tag_type> removed_tags;
        auto                              sk_it = key_shares.begin();
        ++sk_it; // skip the first element
        for (; sk_it != key_shares.end(); ++sk_it) {
            auto tag = crypto::punct::extract_tag(*sk_it);
            logger::logger()->debug("Tag " + utility::hex_string(tag)
                                    + " removed");
            removed_tags.insert(tag);
        }


        // get previously cached elements
        cached_results_edb_.get(req.keyword_token, filtered_cache);

        // filter the previously cached elements to remove newly removed entries
        auto it = filtered_cache.begin();

        while (it != filtered_cache.end()) {
            if (removed_tags.count(it->second) > 0) {
                it = filtered_cache.erase(it);
            } else {
                post_callback(
                    it->first,
                    diana_threads_count); // this job has id diana_threads_count
                ++it;
            }
        }
    };


    // start the cached result job
    std::thread cache_thread = std::thread(cached_res_job);


    // wait for the cache thread to finish
    cache_thread.join();

    // run the search on the insertion SE with the decryption_callback
    // we have to start the cache_thread first because the next call is blocking
    //            insertion_server_.search_parallel(req.insertion_search_request,
    //            decryption_callback, threads_count-1); // one thread is
    //            already in use
    insertion_server_.search(req.insertion_search_request,
                             decryption_callback_unique);

    // merge the new result list with the filtered cache
    new_cache.splice(new_cache.end(), filtered_cache);

    // store results in the cache
    cached_results_edb_.put(req.keyword_token, new_cache);
}


void JanusServer::insert(const InsertionRequest& req)
{
    insertion_server_.insert(req);
}

void JanusServer::remove(const DeletionRequest& req)
{
    deletion_server_.insert(req);
}

void JanusServer::flush_edb()
{
    insertion_server_.flush_edb();
    deletion_server_.flush_edb();
}


} // namespace janus
} // namespace sse
