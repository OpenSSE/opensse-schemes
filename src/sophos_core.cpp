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

#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>

#include <iostream>
#include <algorithm>

namespace sse {
namespace sophos {

#define DERIVATION_KEY "derivation"
#define TDP_KEY "tdp_pk"
#define TOKEN_KEY "tokens"
#define TOKEN_MAP_SIZE_KEY "map_size"

    
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

SophosClient::SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size) :
    k_prf_(), token_map_(token_map_path, tm_setup_size), inverse_tdp_()
{
    load_keyword_indices(keyword_indexer_path);

    keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
    if (!keyword_indexer_stream_.is_open()) {
        keyword_indexer_stream_.close();
        throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
    }
}
    
SophosClient::SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key) :
k_prf_(derivation_master_key), token_map_(token_map_path), inverse_tdp_(tdp_private_key)
{
    load_keyword_indices(keyword_indexer_path);
   
    keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
    if (!keyword_indexer_stream_.is_open()) {
        keyword_indexer_stream_.close();
        throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
    }
}

SophosClient::SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const size_t tm_setup_size) :
k_prf_(derivation_master_key), token_map_(token_map_path,tm_setup_size), inverse_tdp_(tdp_private_key)
{
    load_keyword_indices(keyword_indexer_path);
    
    keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
    if (!keyword_indexer_stream_.is_open()) {
        keyword_indexer_stream_.close();
        throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
    }
}
    

SophosClient::~SophosClient()
{
    keyword_indexer_stream_.close();
}

void SophosClient::load_keyword_indices(const std::string &path)
{
    std::ifstream keyword_indices_in(path);
    
    if(keyword_indices_in)
    {
        bool ret = parse_keyword_map(keyword_indices_in, keyword_indices_);
        
        if (!ret) {
            logger::log(logger::WARNING) << "Error when parsing the keyword indices" << std::endl;
        }
    }
    keyword_indices_in.close();
    
    keyword_counter_ = (uint32_t)keyword_indices_.size();
}

size_t SophosClient::keyword_count() const
{
    return token_map_.size();
}
    
int64_t SophosClient::find_keyword_index(const std::string &kw) const
{
    auto it = keyword_indices_.find(kw);

    if (it == keyword_indices_.end()) {
    return -1;
    }
    
    return it->second;
}

uint32_t SophosClient::get_keyword_index(const std::string &kw)
{
    bool tmp;
    
    return get_keyword_index(kw, tmp);
}
    
uint32_t SophosClient::get_keyword_index(const std::string &kw, bool& is_new)
{
    std::unique_lock<std::mutex> kw_index_lock(kw_index_mtx_, std::defer_lock);
    
    kw_index_lock.lock();
    auto it = keyword_indices_.find(kw);
    kw_index_lock.unlock();
    
    if (it == keyword_indices_.end()) {
        is_new = true;
        // we have to insert the keyword
        kw_index_lock.lock();
        uint32_t c = new_keyword_index(kw);
        kw_index_lock.unlock();
        
        return c;
    }
    
    is_new = false;
    return it->second;
}

uint32_t SophosClient::new_keyword_index(const std::string &kw)
{
    // CAUTION: NOT THREAD SAFE !!!
    uint32_t c = keyword_counter_++;
    keyword_indices_.insert(std::make_pair(kw, c));
    append_keyword_map(keyword_indexer_stream_, kw, c);

    return c;
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
    

SearchRequest   SophosClient::search_request(const std::string &keyword) const
{
    std::pair<search_token_type, uint32_t> search_pair;
    bool found;
    SearchRequest req;
    req.add_count = 0;

    int64_t kw_index = find_keyword_index(keyword);
    
    if (kw_index != -1) {
        found = token_map_.get((uint32_t)kw_index, search_pair);
        
        if(!found)
        {
            logger::log(logger::ERROR) << "No matching token found for keyword " << keyword << " (index " << kw_index << ")" << std::endl;
        }else{
            req.token = search_pair.first;
            req.derivation_key = k_prf_.prf_string(keyword);
            req.add_count = search_pair.second;
        }
    }
    return req;
}
    

UpdateRequest   SophosClient::update_request(const std::string &keyword, const index_type index)
{
    std::pair<search_token_type, uint32_t> search_pair;
    bool found = false, is_new_index = true;
    
    UpdateRequest req;
    search_token_type st;
    
    // get (and possibly construct) the keyword index
    uint32_t kw_index = get_keyword_index(keyword, is_new_index);
    
    
    // if new_index is set to true, we will have to insert a new token in the token map
    // otherwise, search the existing token and update it
    
    if (is_new_index) {
        st = inverse_tdp_.sample_array();
        
        {
            std::lock_guard<std::mutex> lock(token_map_mtx_);
            token_map_.add(kw_index, std::make_pair(st, 1));
        }
        logger::log(logger::DBG) << "ST0 " << logger::hex_string(st) << std::endl;

    }else{
        {
            std::lock_guard<std::mutex> lock(token_map_mtx_);
            found = token_map_.get(kw_index, search_pair);
        }
        
        if (!found) {
            // ERROR
            logger::log(logger::ERROR) << "No matching token found for keyword " << keyword << " (index " << kw_index << ")" << std::endl;
        }else{
            st = inverse_tdp_.invert(search_pair.first);
            
            logger::log(logger::DBG) << "New ST " << logger::hex_string(st) << std::endl;
            
            {
                std::lock_guard<std::mutex> lock(token_map_mtx_);
                token_map_.at(kw_index) = std::make_pair(st, search_pair.second+1);
            }
        }
    }
    
    
    std::string deriv_key = k_prf_.prf_string(keyword);

    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(deriv_key) << std::endl;

    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
    
    std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
    
    req.token = derivation_prf.prf(st_string + '0');
    req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
    
    logger::log(logger::DBG) << "Update token: (" << logger::hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;

    return req;
}

std::ostream& SophosClient::db_to_json(std::ostream& out) const
{
    rapidjson::OStreamWrapper ow(out);
    rapidjson::Writer<rapidjson::OStreamWrapper> writer(ow);
    
    writer.StartObject();
    
    // write the derivation key
    writer.Key(DERIVATION_KEY);
    writer.String(master_derivation_key().c_str());
    
    // write the private key
    writer.Key(TDP_KEY);
    writer.String(private_key().c_str());

    // write the token array
    writer.Key(TOKEN_MAP_SIZE_KEY);
    writer.Uint64(token_map_.bucket_space());

    // write the token array
    writer.Key(TOKEN_KEY);
    writer.StartObject();
    
    for (const auto& kw_pair : keyword_indices_) {
        writer.Key(kw_pair.first.c_str());
        writer.StartArray();
        
        auto token = token_map_.at(kw_pair.second);
        
        writer.String((const char*)token.first.data(),token.first.size());
        writer.Uint(token.second);
        
        writer.EndArray();
    }
    writer.EndObject();
    
    // we are done now
    writer.EndObject();
    
    
    return out;
}
    
std::ostream& SophosClient::print_stats(std::ostream& out) const
{
    out << "Number of keywords: " << token_map_.size() << std::endl;
    out << "Load: " << token_map_.load() << std::endl;
    out << "Overflow bucket size: " << token_map_.overflow_size() << std::endl;
    
    return out;
}

class SophosClient::JSONHandler : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, JSONHandler>
{
public:
    JSONHandler(const std::string& token_map_path, const std::string& keyword_indexer_path)
    : state_(kExpectStart), token_map_path_(token_map_path), keyword_indexer_path_(keyword_indexer_path)
    {
    }
    
    bool StartObject() {
        switch (state_) {
            case kExpectStart:
                state_ = kExpectStart;
                return true;
            case kExpectTokenValuesStart:
                state_ = kExpectTokenKey;
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse object start" << std::endl;

                return false;
        }
    }
    
    bool EndObject(rapidjson::SizeType) {
        
        switch (state_) {
            case kExpectEnd:
                return true;
            case kExpectTokenKey:
                state_ = kExpectEnd;
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse object end" << std::endl;
                
                return false;
        }
    }

    bool Key(const char* str, rapidjson::SizeType length, bool) {
        std::string key(str, length);
        switch (state_) {
            case kExpectParameterKey:
                
                if (key == DERIVATION_KEY) {
                    state_ = kExpectDerivationKeyValue;
                }else if (key == TDP_KEY) {
                    state_ = kExpectTDPKeyValue;
                }else if (key == TOKEN_MAP_SIZE_KEY) {
                    state_ = kExpectTokenMapSizeValue;
                }else if (key == TOKEN_KEY) {
                    // we have to check that we parsed all the parameters
                    if( bucket_map_size_ == 0 || derivation_key_.size() == 0 || tdp_key_.size() == 0 )
                    {
                        logger::log(logger::ERROR) << "Parsing error. At least one parameter is missing" << std::endl;
                        return false;
                    }
                    
                    // construct the client from the parameters
                    client_ = new SophosClient(token_map_path_, keyword_indexer_path_, tdp_key_, derivation_key_);
                    state_ = kExpectTokenValuesStart;
                }else{
                    logger::log(logger::ERROR) << "Parsing error. Invalid key " << key  << std::endl;

                    return false;
                }
                
                return true;
            case kExpectKeyword:
                current_keyword_ = key;
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse key " << key  << std::endl;

                return false;
        }
    }

    bool StartArray() {
        switch(state_) {
            case kExpectStartList:
                state_ = kExpectTokenKey;
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse array start" << std::endl;

                return false;
                
        }
    }
    
    bool EndArray(rapidjson::SizeType elementCount) {
        switch(state_){
            case kExpectEndList:
            {
                state_ = kExpectKeyword;
                
                // add a keyword with the parsed token and count
                uint32_t index = client_->get_keyword_index(current_keyword_);
                client_->token_map_.add(index, std::make_pair(current_st_, current_count_));
                
                return true;
            }
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse array end" << std::endl;
                return false;
        }
    }

    bool String(const Ch* str, rapidjson::SizeType length, bool copy) {
        std::string in(str, length);
        switch(state_){
            case kExpectDerivationKeyValue:
                derivation_key_ = in;
                return true;
            case kExpectTDPKeyValue:
                tdp_key_ = in;
                return true;
            case kExpectTokenKey:
                std::copy(in.begin(), in.end(), current_st_.begin());
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse string " << in << std::endl;
                return false;
        }
    }
    bool Uint(unsigned i) {
        switch (state_) {
            case kExpectTokenMapSizeValue:
                bucket_map_size_ = i;
                return true;
            case kExpectTokenCount:
                current_count_ = i;
                return true;
            default:
                logger::log(logger::ERROR) << "Parsing error. Invalid state to parse int " << i << std::endl;
                return false;
        }
    }
    
    bool Default() {
        logger::log(logger::ERROR) << "Parsing error. Unsupported input " << std::endl;
        return false;
    } // All other events are invalid.

    SophosClient* client()
    {
        return client_;
    }
    
private:
    enum State {
        kExpectStart,
        kExpectParameterKey,
        kExpectDerivationKeyValue,
        kExpectTDPKeyValue,
        kExpectTokenMapSizeValue,
        kExpectTokenValuesStart,
        kExpectKeyword,
        kExpectTokenKey,
        kExpectTokenCount,
        kExpectStartList,
        kExpectEndList,
        kExpectEnd
    } state_;

    SophosClient* client_;
    
    const std::string& token_map_path_;
    const std::string& keyword_indexer_path_;
    
    size_t bucket_map_size_;
    std::string derivation_key_;
    std::string tdp_key_;
    
    std::string current_keyword_;
    search_token_type current_st_;
    uint32_t current_count_;
};
    
std::unique_ptr<SophosClient> SophosClient::construct_from_json(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& json_path)
{
    FILE* fp = fopen(json_path.c_str(), "r");
    char readBuffer[65536];
    rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
    
    JSONHandler handler(token_map_path, keyword_indexer_path);
    rapidjson::Reader reader;
    
    reader.Parse(is, handler);
    
    fclose(fp);
    
    return std::unique_ptr<SophosClient>(handler.client());
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
        
        access_pool.join();
        
        return results;
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
