//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

#include "utils.hpp"
#include "logger.hpp"
#include "thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
namespace sophos {
    
    const std::string SophosClient::tdp_sk_file__ = "tdp_sk.key";
    const std::string SophosClient::derivation_key_file__ = "derivation_master.key";

size_t TokenHasher::operator()(const update_token_type& ut) const
{
    size_t h = 0;
    for (size_t i = 0; i < kUpdateTokenSize; i++) {
        if (i > 0) {
            h <<= 8;
        }
        h = ut[i] + h;
    }
    return h;
}

SophosClient::SophosClient() :
    k_prf_(), inverse_tdp_()
{
}
    
SophosClient::SophosClient(const std::string& tdp_private_key, const std::string& derivation_master_key) :
k_prf_(derivation_master_key), inverse_tdp_(tdp_private_key)
{
}

SophosClient::~SophosClient()
{
    
}

const std::string SophosClient::public_key() const
{
    return inverse_tdp_.public_key();
}

const std::string SophosClient::private_key() const
{
    return inverse_tdp_.private_key();
}
    
const std::string SophosClient::master_derivation_key() const
{
    return std::string(k_prf_.key().begin(), k_prf_.key().end());
}

const crypto::Prf<kDerivationKeySize>& SophosClient::derivation_prf() const
{
    return k_prf_;
}
const sse::crypto::TdpInverse& SophosClient::inverse_tdp() const
{
    return inverse_tdp_;
}
    
void SophosClient::write_keys(const std::string& dir_path) const
{
    if (!is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }
    
    std::string sk_path = dir_path + "/" + tdp_sk_file__;
    std::string master_key_path = dir_path + "/" + derivation_key_file__;

    std::ofstream sk_out(sk_path.c_str());
    if (!sk_out.is_open()) {
        throw std::runtime_error(sk_path + ": unable to write the secret key");
    }
    
    sk_out << private_key();
    sk_out.close();
    
    std::ofstream master_key_out(master_key_path.c_str());
    if (!master_key_out.is_open()) {
        throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
    }
    
    master_key_out << master_derivation_key();
    master_key_out.close();

}
    
SophosServer::SophosServer(const std::string& db_path, const std::string& tdp_pk) :
edb_(db_path), public_tdp_(tdp_pk, std::thread::hardware_concurrency())
{
    
}

SophosServer::SophosServer(const std::string& db_path, const size_t tm_setup_size, const std::string& tdp_pk) :
edb_(db_path, tm_setup_size), public_tdp_(tdp_pk, std::thread::hardware_concurrency())
{
    
}

const std::string SophosServer::public_key() const
{
    return public_tdp_.public_key();
}

std::list<index_type> SophosServer::search(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;

    logger::log(logger::DBG) << "Search token: " << logger::hex_string(req.token) << std::endl;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(req.derivation_key) << std::endl;

    for (size_t i = 0; i < req.add_count; i++) {
        std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        update_token_type ut = derivation_prf.prf(st_string + '0');

        logger::log(logger::DBG) << "Derived token: " << logger::hex_string(ut) << std::endl;

        bool found = edb_.get(ut,r);
        
        if (found) {
            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            
            r = xor_mask(r, derivation_prf.prf(st_string + '1'));
            results.push_back(r);
        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }
        
        st = public_tdp_.eval(st);
    }
    
    return results;
}

std::list<index_type> SophosServer::search_parallel(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;
    
    logger::log(logger::DBG) << "Search token: " << logger::hex_string(req.token) << std::endl;
    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(req.derivation_key) << std::endl;

    ThreadPool prf_pool(1);
    ThreadPool token_map_pool(1);
    ThreadPool decrypt_pool(1);

    auto decrypt_job = [&derivation_prf, &results](const index_type r, const std::string& st_string)
    {
        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
        results.push_back(v);
    };

    auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
    {
        index_type r;
        
        logger::log(logger::DBG) << "Derived token: " << logger::hex_string(token) << std::endl;
        
        bool found = edb_.get(token,r);
        
        if (found) {
            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            
//            r = xor_mask(r, derivation_prf.prf(st_string + '1'));
//            results.push_back(r);
            
            decrypt_pool.enqueue(decrypt_job, r, st_string);

        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

    };

    
    auto derive_job = [&derivation_prf,&token_map_pool,&lookup_job](const std::string& input_string)
    {
        update_token_type ut = derivation_prf.prf(input_string + '0');
        
        token_map_pool.enqueue(lookup_job, input_string, ut);
        
    };

    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto rsa_job = [this, &st, &derive_job, &prf_pool](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }
        
        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            prf_pool.enqueue(derive_job, st_string);
        }
        
        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);
            
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            prf_pool.enqueue(derive_job, st_string);
        }
    };
    
    std::vector<std::thread> rsa_threads;
    
    unsigned n_threads = std::thread::hardware_concurrency()-3;
    
//    std::cout << "Running RSA on " << n_threads << " threads" << std::endl;
    
    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, n_threads));
    }
 
    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads[t].join();
    }

//    for (size_t i = 0; i < req.add_count; i++) {
//        std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
//        prf_pool.enqueue(derive_job, st_string);
//        
//        st = public_tdp_.eval(st);
//    }
    
    prf_pool.join();
    token_map_pool.join();
    
    
    return results;
}

std::list<index_type> SophosServer::search_parallel_light(const SearchRequest& req, uint8_t access_threads)
{
    std::list<index_type> results;
    std::mutex res_mutex;
    
    search_token_type st = req.token;
    
    logger::log(logger::DBG) << "Search token: " << logger::hex_string(req.token) << std::endl;
    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(req.derivation_key) << std::endl;
    
    ThreadPool access_pool(access_threads);
    
    std::atomic_uint c(0);
    
    auto access_job = [&derivation_prf, this, &results, &res_mutex](const std::string& st_string)
    {
        update_token_type token = derivation_prf.prf(st_string + '0');

        index_type r;
        
        logger::log(logger::DBG) << "Derived token: " << logger::hex_string(token) << std::endl;
        
        bool found = edb_.get(token,r);
        
        if (found) {
            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;

        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }
        
        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
        
        res_mutex.lock();
        results.push_back(v);
        res_mutex.unlock();
        
    };
    
    
    
    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto rsa_job = [this, &st, &access_job, &access_pool](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }
        
        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            access_pool.enqueue(access_job, st_string);
        }
        
        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);
            
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            access_pool.enqueue(access_job, st_string);

        }
    };
    
    std::vector<std::thread> rsa_threads;
    
    unsigned n_threads = std::thread::hardware_concurrency()-access_threads;
    
    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, n_threads));
    }
    
    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads[t].join();
    }
    
    access_pool.join();
    
    return results;
}

    void SophosServer::search_parallel_light_callback(const SearchRequest& req, uint8_t access_threads, std::function<void(index_type)> post_callback, uint8_t post_threads)
    {
        search_token_type st = req.token;
        
        logger::log(logger::DBG) << "Search token: " << logger::hex_string(req.token) << std::endl;
        
        auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
        
        logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(req.derivation_key) << std::endl;
        
        ThreadPool access_pool(access_threads);
        ThreadPool post_pool(post_threads);
        
        std::atomic_uint c(0);
                
        auto access_job = [&derivation_prf, this, &post_pool, &post_callback](const std::string& st_string)
        {
            update_token_type token = derivation_prf.prf(st_string + '0');
            
            index_type r;
            
            logger::log(logger::DBG) << "Derived token: " << logger::hex_string(token) << std::endl;
            
            bool found = edb_.get(token,r);
            
            if (found) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                
            }else{
                logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
            }
            
            index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
            
//            res_mutex.lock();
//            results.push_back(v);
//            res_mutex.unlock();
            post_pool.enqueue(post_callback, v);
            
        };
        
        
        
        // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
        auto rsa_job = [this, &st, &access_job, &access_pool](const uint8_t index, const size_t max, const uint8_t N)
        {
            search_token_type local_st = st;
            if (index != 0) {
                local_st = public_tdp_.eval(local_st, index);
            }
            
            if (index < max) {
                // this is a valid search token, we have to derive it and do a lookup
                std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
                access_pool.enqueue(access_job, st_string);
            }
            
            for (size_t i = index+N; i < max; i+=N) {
                local_st = public_tdp_.eval(local_st, N);
                
                std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
                access_pool.enqueue(access_job, st_string);
                
            }
        };
        
        std::vector<std::thread> rsa_threads;
        
        unsigned n_threads = std::thread::hardware_concurrency()-access_threads;
        
        for (uint8_t t = 0; t < n_threads; t++) {
            rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, n_threads));
        }
        
        for (uint8_t t = 0; t < n_threads; t++) {
            rsa_threads[t].join();
        }
        
        access_pool.join();
    }

void SophosServer::update(const UpdateRequest& req)
{
    logger::log(logger::DBG) << "Update: (" << logger::hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;

    edb_.add(req.token, req.index);
}

std::ostream& SophosServer::print_stats(std::ostream& out) const
{
    out << "Number of tokens: " << edb_.size() << std::endl;
    out << "Load: " << edb_.load() << std::endl;
    out << "Overflow bucket size: " << edb_.overflow_size() << std::endl;
    
    return out;
}

} // namespace sophos
} // namespace sse
