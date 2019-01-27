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

#include <sse/schemes/diana/diana_common.hpp>
#include <sse/schemes/diana/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>
#include <sse/schemes/utils/thread_pool.hpp>

#include <sse/crypto/prf.hpp>

namespace sse {
namespace diana {


template<typename T>
class DianaServer
{
public:
    static constexpr size_t kKeySize = 32;

    using index_type = T;
    // Callback only taking the result as input
    using basic_callback_type = std::function<void(index_type)>;
    // Callback taking the position of the result in the result list (i.e. n if
    // it is the n-th element in the insertion order), the result and the thread
    // id as input. In this implementation, this callback is guaranteed to be
    // called by only one thread (hence the tl prefix for 'thread local')
    using tl_callback_type = std::function<void(size_t, index_type, uint8_t)>;


    explicit DianaServer(const std::string& db_path);

    std::list<index_type> search(const SearchRequest& req,
                                 bool                 delete_results = false);
    void                  search(const SearchRequest&       req,
                                 const basic_callback_type& post_callback,
                                 bool                       delete_results = false);

    std::list<index_type> search_parallel(const SearchRequest& req,
                                          uint8_t              threads_count,
                                          bool delete_results = false);
    void                  search_parallel(const SearchRequest&     req,
                                          uint8_t                  threads_count,
                                          std::vector<index_type>& results,
                                          bool                     delete_results = false);
    void                  search_parallel(const SearchRequest&       req,
                                          const basic_callback_type& post_callback,
                                          uint8_t                    threads_count,
                                          bool                       delete_results = false);
    void                  search_parallel(const SearchRequest&    req,
                                          const tl_callback_type& post_callback,
                                          uint8_t                 threads_count,
                                          bool                    delete_results = false);


    void insert(const UpdateRequest<index_type>& req);

    void flush_edb();

private:
    bool get_unmask(uint8_t* key, index_type& index, bool delete_key);

    inline bool retrieve_entry(const update_token_type& key,
                               index_type&              index,
                               bool                     delete_key)
    {
        bool found = edb_.get(key, index);
        if (delete_key && found) {
            edb_.remove(key);
        }

        return found;
    }


    sophos::RockDBWrapper edb_;
};

} // namespace diana
} // namespace sse

namespace sse {
namespace diana {

template<typename T>
DianaServer<T>::DianaServer(const std::string& db_path) : edb_(db_path)
{
}

template<typename T>
bool DianaServer<T>::get_unmask(uint8_t*    key,
                                index_type& index,
                                bool        delete_key)
{
    update_token_type ut;
    index_type        mask;

    logger::logger()->debug(
        "Derived leaf token: "
        + utility::hex_string(std::string(reinterpret_cast<const char*>(key),
                                          kSearchTokenKeySize)));

    gen_update_token_mask<T>(key, ut, mask);


    logger::logger()->debug("Derived token : " + utility::hex_string(ut)
                            + " Mask : " + utility::hex_string(mask));

    bool found = retrieve_entry(ut, index, delete_key);

    if (found) {
        logger::logger()->debug("Found: " + utility::hex_string(index));

        index = xor_mask(index, mask);
    } else {
        /* LCOV_EXCL_START */
        logger::logger()->error(
            "We were supposed to find an entry. Accessed key: "
            + utility::hex_string(ut));
        /* LCOV_EXCL_STOP */
    }

    return found;
}

template<typename T>
std::list<typename DianaServer<T>::index_type> DianaServer<T>::search(
    const SearchRequest& req,
    bool                 delete_results)
{
    std::list<index_type> results;

    auto callback = [&results](index_type i) { results.push_back(i); };

    search(req, callback, delete_results);

    return results;
}

template<typename T>
void DianaServer<T>::search(const SearchRequest&       req,
                            const basic_callback_type& post_callback,
                            bool                       delete_results)
{
    logger::logger()->debug("Search: {} expected matches.", req.add_count);

    // if the search request is empty, return immediately
    if (req.add_count == 0) {
        return;
    }

    auto eval_callback
        // cppcheck-suppress variableScope
        = [this, &post_callback, delete_results](uint64_t /*leaf_index*/,
                                                 search_token_key_type st) {
              index_type index;
              if (get_unmask(st.data(), index, delete_results)) {
                  post_callback(index);
              }
          };
    req.constrained_rcprf.eval_range(
        0, req.constrained_rcprf.max_leaf(), eval_callback);
}

template<typename T>
std::list<typename DianaServer<T>::index_type> DianaServer<T>::search_parallel(
    const SearchRequest& req,
    uint8_t              threads_count,
    bool                 delete_results)
{
    assert(threads_count > 0);

    // if the search request is empty, return immediately
    if (req.add_count == 0) {
        return {};
    }

    // use one result list per thread so to avoid using locks
    std::list<index_type>* result_lists
        = new std::list<index_type>[threads_count];

    auto callback
        = [&result_lists](size_t /*i*/, index_type res, uint8_t thread_id) {
              result_lists[thread_id].push_back(res);
          };

    search_parallel(req, callback, threads_count, delete_results);

    // merge the result lists
    std::list<index_type> results(std::move(result_lists[0]));
    for (uint8_t i = 1; i < threads_count; i++) {
        results.splice(results.end(), result_lists[i]);
    }

    delete[] result_lists;

    return results;
}

template<typename T>
void DianaServer<T>::search_parallel(const SearchRequest&     req,
                                     uint8_t                  threads_count,
                                     std::vector<index_type>& results,
                                     bool                     delete_results)
{
    if (results.size() < req.add_count) {
        // resize the vector if needed
        results.resize(req.add_count);
    }


    auto callback = [&results](size_t i, index_type res, uint8_t
                               /*thread_id*/) {
        if (__builtin_expect(i < results.size(), 1)) {
            results[i] = res;
        }
    };

    search_parallel(req, callback, threads_count, delete_results);
}

template<typename T>
void DianaServer<T>::search_parallel(const SearchRequest&       req,
                                     const basic_callback_type& post_callback,
                                     uint8_t                    threads_count,
                                     bool                       delete_results)
{
    auto aux
        = [&post_callback](size_t /*i*/, index_type ind, uint8_t /*t_id*/) {
              post_callback(ind);
          };
    search_parallel(req, aux, threads_count, delete_results);
}

template<typename T>
void DianaServer<T>::search_parallel(const SearchRequest&    req,
                                     const tl_callback_type& post_callback,
                                     uint8_t                 threads_count,
                                     bool                    delete_results)
{
    assert(threads_count > 0);
    if (req.add_count == 0) {
        return;
    }


    auto job = [this, &req, &post_callback, delete_results](
                   const uint8_t t_id,
                   const size_t  min_index,
                   const size_t  max_index) {
        auto eval_callback
            // cppcheck does not like nested lambda
            // cppcheck-suppress shadowVar
            // Silence issues with cppcheck on lambda's variable scope
            // cppcheck-suppress variableScope
            = [this, &post_callback, delete_results, t_id](
                  uint64_t leaf_index, search_token_key_type st) {
                  index_type index;
                  if (get_unmask(st.data(), index, delete_results)) {
                      post_callback(leaf_index, index, t_id);
                  }
              };
        req.constrained_rcprf.eval_range(min_index, max_index, eval_callback);
    };

    std::vector<std::thread> threads;

    threads_count = std::min<uint8_t>(
        std::min<uint32_t>(threads_count, req.add_count), 0xFF);


    size_t step      = req.add_count / threads_count;
    size_t remaining = req.add_count % threads_count;

    size_t min = 0;
    size_t max = step;

    for (uint8_t t = 0; t < threads_count; t++) {
        if (t < remaining) {
            max++;
        }

        threads.push_back(
            std::thread(job, t, min, std::min<size_t>(max, req.add_count) - 1));

        min = max;
        max += step;
    }

    for (auto& t : threads) {
        t.join();
    }
}

template<typename T>
void DianaServer<T>::insert(const UpdateRequest<T>& req)
{
    logger::logger()->debug("Received update: ("
                            + utility::hex_string(req.token) + ", "
                            + utility::hex_string(req.index) + ")");

    edb_.put(req.token, req.index);
}

template<typename T>
void DianaServer<T>::flush_edb()
{
    edb_.flush();
}
} // namespace diana
} // namespace sse
