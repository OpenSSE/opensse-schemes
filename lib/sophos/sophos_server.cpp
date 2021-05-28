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


#include <sse/schemes/sophos/sophos_server.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/thread_pool.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <algorithm>
#include <iostream>

namespace sse {
namespace sophos {


SophosServer::SophosServer(const std::string& db_path,
                           const std::string& tdp_pk)
    : edb_(db_path),
      public_tdp_(tdp_pk, 2 * std::thread::hardware_concurrency())
{
}

std::string SophosServer::public_key() const
{
    return public_tdp_.public_key();
}

std::list<index_type> SophosServer::search(SearchRequest& req)
{
    std::list<index_type> results;

    search_token_type st = req.token;

    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));


    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    for (size_t i = 0; i < req.add_count; i++) {
        index_type                            r;
        update_token_type                     ut;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(derivation_prf, st.data(), ut, mask);

        logger::logger()->debug("Search token: ("
                                + std::to_string(req.add_count - i - 1) + ", "
                                + utility::hex_string(st) + ")\nDerived token: "
                                + utility::hex_string(ut));


        bool found = edb_.get(ut, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));

            r = utility::xor_mask(r, mask);
            results.push_back(r);
        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error("We were supposed to find something!");
            /* LCOV_EXCL_STOP */
        }

        st = public_tdp_.eval(st);
    }

    return results;
} // namespace sophos

void SophosServer::search_callback(
    SearchRequest&                         req,
    const std::function<void(index_type)>& post_callback)
{
    search_token_type st = req.token;


    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));

    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    for (size_t i = 0; i < req.add_count; i++) {
        index_type                            r;
        update_token_type                     ut;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(derivation_prf, st.data(), ut, mask);

        logger::logger()->debug("Derived token: " + utility::hex_string(ut));

        bool found = edb_.get(ut, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));
            r = utility::xor_mask(r, mask);
            post_callback(r);
        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error("We were supposed to find something!");
            /* LCOV_EXCL_STOP */
        }

        st = public_tdp_.eval(st);
    }
}

std::list<index_type> SophosServer::search_parallel(SearchRequest& req,
                                                    uint8_t access_threads)
{
    std::list<index_type> results;
    std::mutex            res_mutex;

    search_token_type st = req.token;

    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));


    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    ThreadPool access_pool(access_threads);

    auto access_job = [&derivation_prf, this, &results, &res_mutex](
                          const std::string& st_string) {
        update_token_type                     token;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(
            derivation_prf,
            reinterpret_cast<const uint8_t*>(st_string.data()),
            token,
            mask);

        index_type r;

        logger::logger()->debug("Derived token: " + utility::hex_string(token));

        bool found = edb_.get(token, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));
        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error("We were supposed to find something!");
            return;
            /* LCOV_EXCL_STOP */
        }

        index_type v = utility::xor_mask(r, mask);

        res_mutex.lock();
        results.push_back(v);
        res_mutex.unlock();
    };


    // the rsa job launched with input index,max computes all the RSA tokens of
    // order i + kN up to max
    auto rsa_job = [this, &st, &access_job, &access_pool](
                       const uint8_t index, const size_t max, const uint8_t N) {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a
            // lookup
            std::string st_string(reinterpret_cast<char*>(local_st.data()),
                                  local_st.size());
            access_pool.enqueue(access_job, st_string);
        }

        for (size_t i = index + N; i < max; i += N) {
            local_st = public_tdp_.eval(local_st, N);

            std::string st_string(reinterpret_cast<char*>(local_st.data()),
                                  local_st.size());
            access_pool.enqueue(access_job, st_string);
        }
    };

    std::vector<std::thread> rsa_threads;

    // use at least two threads to make the RSA computations
    unsigned n_rsa_threads
        = std::max<unsigned>(std::thread::hardware_concurrency(), 2);

    for (unsigned t = 0; t < n_rsa_threads; t++) {
        rsa_threads.emplace_back(rsa_job, t, req.add_count, n_rsa_threads);
    }

    for (unsigned t = 0; t < n_rsa_threads; t++) {
        rsa_threads[t].join();
    }

    access_pool.join();

    return results;
}

std::list<index_type> SophosServer::search_parallel_light(SearchRequest& req,
                                                          uint8_t thread_count)
{
    search_token_type     st = req.token;
    std::list<index_type> results;
    std::mutex            res_mutex;

    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));

    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    auto derive_access = [&derivation_prf, this, &results, &res_mutex](
                             const search_token_type st, size_t i) {
        update_token_type                     token;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(derivation_prf, st.data(), token, mask);


        index_type r;

        logger::logger()->debug("Derived token: " + utility::hex_string(token));

        bool found = edb_.get(token, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));

            index_type v = utility::xor_mask(r, mask);

            res_mutex.lock();
            results.push_back(v);
            res_mutex.unlock();

        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error(
                "We were supposed to find a value mapped to key "
                + utility::hex_string(token) + " (" + std::to_string(i)
                + "-th derived key from search token " + utility::hex_string(st)
                + ")");
            /* LCOV_EXCL_STOP */
        }
    };


    // the rsa job launched with input index,max computes all the RSA tokens of
    // order i + kN up to max
    auto job = [this, &st, &derive_access](
                   const uint8_t index, const size_t max, const uint8_t N) {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a
            // lookup

            derive_access(local_st, index);
        }

        for (size_t i = index + N; i < max; i += N) {
            local_st = public_tdp_.eval(local_st, N);

            derive_access(local_st, index);
        }
    };

    std::vector<std::thread> rsa_threads;

    //    unsigned n_threads =
    //    std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads.emplace_back(job, t, req.add_count, thread_count);
    }

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads[t].join();
    }

    return results;
}

void SophosServer::search_parallel_callback(
    SearchRequest&                  req,
    std::function<void(index_type)> post_callback,
    uint8_t                         rsa_thread_count,
    uint8_t                         access_thread_count,
    uint8_t                         post_thread_count)
{
    search_token_type st = req.token;


    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));

    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    ThreadPool access_pool(access_thread_count);
    ThreadPool post_pool(post_thread_count);

    auto access_job = [&derivation_prf, this, &post_pool, &post_callback](
                          const search_token_type st, size_t i) {
        update_token_type                     token;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(derivation_prf, st.data(), token, mask);

        index_type r;

        logger::logger()->debug("Derived token: " + utility::hex_string(token));

        bool found = edb_.get(token, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));

            index_type v = utility::xor_mask(r, mask);

            post_pool.enqueue(post_callback, v);

        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error(
                "We were supposed to find a value mapped to key "
                + utility::hex_string(token) + " (" + std::to_string(i)
                + "-th derived key from search token " + utility::hex_string(st)
                + ")");
            /* LCOV_EXCL_STOP */
        }
    };


    // the rsa job launched with input index,max computes all the RSA tokens of
    // order i + kN up to max
    auto rsa_job = [this, &st, &access_job, &access_pool](
                       const uint8_t index, const size_t max, const uint8_t N) {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a
            // lookup
            access_pool.enqueue(access_job, local_st, index);
        }

        for (size_t i = index + N; i < max; i += N) {
            local_st = public_tdp_.eval(local_st, N);

            access_pool.enqueue(access_job, local_st, i);
        }
    };

    std::vector<std::thread> rsa_threads;

    //    unsigned n_threads =
    //    std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < rsa_thread_count; t++) {
        rsa_threads.emplace_back(rsa_job, t, req.add_count, rsa_thread_count);
    }

    for (uint8_t t = 0; t < rsa_thread_count; t++) {
        rsa_threads[t].join();
    }

    access_pool.join();
    post_pool.join();
}

void SophosServer::search_parallel_light_callback(
    SearchRequest&                  req,
    std::function<void(index_type)> post_callback,
    uint8_t                         thread_count)
{
    search_token_type st = req.token;

    logger::logger()->debug("Search token: " + utility::hex_string(req.token)
                            + "\nDerivation key: "
                            + utility::hex_string(req.derivation_key));

    crypto::Prf<kUpdateTokenSize> derivation_prf(
        crypto::Key<kDerivationKeySize>(req.derivation_key.data()));

    auto derive_access = [&derivation_prf, this, &post_callback](
                             const search_token_type st, size_t i) {
        update_token_type                     token;
        std::array<uint8_t, kUpdateTokenSize> mask;
        gen_update_token_masks(derivation_prf, st.data(), token, mask);

        index_type r;

        logger::logger()->debug("Derived token: " + utility::hex_string(token));

        bool found = edb_.get(token, r);

        if (found) {
            logger::logger()->debug("Found: " + utility::hex_string(r));

            index_type v = utility::xor_mask(r, mask);

            post_callback(v);

        } else {
            /* LCOV_EXCL_START */
            logger::logger()->error(
                "We were supposed to find a value mapped to key "
                + utility::hex_string(token) + " (" + std::to_string(i)
                + "-th derived key from search token " + utility::hex_string(st)
                + ")");
            /* LCOV_EXCL_STOP */
        }
    };


    // the rsa job launched with input index,max computes all the RSA tokens of
    // order i + kN up to max
    auto job = [this, &st, &derive_access](
                   const uint8_t index, const size_t max, const uint8_t N) {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a
            // lookup

            derive_access(local_st, index);
        }

        for (size_t i = index + N; i < max; i += N) {
            local_st = public_tdp_.eval(local_st, N);

            derive_access(local_st, index);
        }
    };

    std::vector<std::thread> rsa_threads;

    //    unsigned n_threads =
    //    std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads.emplace_back(job, t, req.add_count, thread_count);
    }

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads[t].join();
    }
}

void SophosServer::insert(const UpdateRequest& req)
{
    logger::logger()->debug("Update: (" + utility::hex_string(req.token) + ", "
                            + utility::hex_string(req.index) + ")");

    //    edb_.add(req.token, req.index);
    edb_.put(req.token, req.index);
}
} // namespace sophos
} // namespace sse
