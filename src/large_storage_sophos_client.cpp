//
//  large_storage_sophos_client.cpp
//  sophos
//
//  Created by Raphael Bost on 13/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "large_storage_sophos_client.hpp"
#include "utils.hpp"
#include "logger.hpp"


#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>


#define DERIVATION_KEY "derivation"
#define TDP_KEY "tdp_pk"
#define TOKEN_KEY "tokens"
#define TOKEN_MAP_SIZE_KEY "map_size"


namespace sse {
    namespace sophos {

        const std::string LargeStorageSophosClient::token_map_file__ = "tokens.dat";
        const std::string LargeStorageSophosClient::keyword_counter_file__ = "keywords.csv";
        
        
        std::unique_ptr<SophosClient> LargeStorageSophosClient::construct_from_directory(const std::string& dir_path)
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string token_map_path = dir_path + "/" + token_map_file__;
            std::string keyword_index_path = dir_path + "/" + keyword_counter_file__;
            
            
            if (!is_file(sk_path)) {
                // error, the secret key file is not there
                throw std::runtime_error("Missing secret key file");
            }
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_directory(token_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing token data");
            }
            if (!is_file(keyword_index_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing keyword indices");
            }
            
            std::ifstream sk_in(sk_path.c_str());
            std::ifstream master_key_in(master_key_path.c_str());
            std::stringstream sk_buf, master_key_buf, rsa_prg_key_buf;
            
            sk_buf << sk_in.rdbuf();
            master_key_buf << master_key_in.rdbuf();
            
            return std::unique_ptr<SophosClient>(new  LargeStorageSophosClient(token_map_path, keyword_index_path, sk_buf.str(), master_key_buf.str()));
        }

        std::unique_ptr<SophosClient> LargeStorageSophosClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string token_map_path = dir_path + "/" + token_map_file__;
            std::string keyword_index_path = dir_path + "/" + keyword_counter_file__;
            
            auto c_ptr =  std::unique_ptr<SophosClient>(new LargeStorageSophosClient(token_map_path, keyword_index_path, n_keywords));
            
            c_ptr->write_keys(dir_path);
            
            return c_ptr;
        }

        LargeStorageSophosClient::LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size) :
        SophosClient(), token_map_(token_map_path, tm_setup_size)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        LargeStorageSophosClient::LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key) :
        SophosClient(tdp_private_key, derivation_master_key), token_map_(token_map_path)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        LargeStorageSophosClient::LargeStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const size_t tm_setup_size) :
        SophosClient(tdp_private_key, derivation_master_key), token_map_(token_map_path,tm_setup_size)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        
        LargeStorageSophosClient::~LargeStorageSophosClient()
        {
            keyword_indexer_stream_.close();
        }
        
        void LargeStorageSophosClient::load_keyword_indices(const std::string &path)
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
        
        size_t LargeStorageSophosClient::keyword_count() const
        {
            return token_map_.size();
        }
        
        int64_t LargeStorageSophosClient::find_keyword_index(const std::string &kw) const
        {
            auto it = keyword_indices_.find(kw);
            
            if (it == keyword_indices_.end()) {
                return -1;
            }
            
            return it->second;
        }
        
        uint32_t LargeStorageSophosClient::get_keyword_index(const std::string &kw)
        {
            bool tmp;
            
            return get_keyword_index(kw, tmp);
        }
        
        uint32_t LargeStorageSophosClient::get_keyword_index(const std::string &kw, bool& is_new)
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
        
        uint32_t LargeStorageSophosClient::new_keyword_index(const std::string &kw)
        {
            // CAUTION: NOT THREAD SAFE !!!
            uint32_t c = keyword_counter_++;
            keyword_indices_.insert(std::make_pair(kw, c));
            append_keyword_map(keyword_indexer_stream_, kw, c);
            
            return c;
        }
        
        SearchRequest   LargeStorageSophosClient::search_request(const std::string &keyword) const
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
                    req.derivation_key = derivation_prf().prf_string(keyword);
                    req.add_count = search_pair.second;
                }
            }
            return req;
        }
        
        
        UpdateRequest   LargeStorageSophosClient::update_request(const std::string &keyword, const index_type index)
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
                st = inverse_tdp().sample_array();
                
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    token_map_.add(kw_index, std::make_pair(st, 1));
                }
                logger::log(logger::DBG) << "ST0 " << hex_string(st) << std::endl;
                
            }else{
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    found = token_map_.get(kw_index, search_pair);
                }
                
                if (!found) {
                    // ERROR
                    logger::log(logger::ERROR) << "No matching token found for keyword " << keyword << " (index " << kw_index << ")" << std::endl;
                }else{
                    st = inverse_tdp().invert(search_pair.first);
                    
                    logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
                    
                    {
                        std::lock_guard<std::mutex> lock(token_map_mtx_);
                        token_map_.at(kw_index) = std::make_pair(st, search_pair.second+1);
                    }
                }
            }
            
            
            std::string deriv_key = derivation_prf().prf_string(keyword);
            
            logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            
            
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
            
            std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
            
            req.token = derivation_prf.prf(st_string + '0');
            req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
            
            logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            
            return req;
        }
        
        std::ostream& LargeStorageSophosClient::db_to_json(std::ostream& out) const
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
        
        std::ostream& LargeStorageSophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << token_map_.size() << std::endl;
            out << "Load: " << token_map_.load() << std::endl;
            out << "Overflow bucket size: " << token_map_.overflow_size() << std::endl;
            
            return out;
        }

        class LargeStorageSophosClient::JSONHandler : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, JSONHandler>
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
                            client_ = new LargeStorageSophosClient(token_map_path_, keyword_indexer_path_, tdp_key_, derivation_key_);
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
            
            LargeStorageSophosClient* client()
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
            
            LargeStorageSophosClient* client_;
            
            const std::string& token_map_path_;
            const std::string& keyword_indexer_path_;
            
            size_t bucket_map_size_;
            std::string derivation_key_;
            std::string tdp_key_;
            
            std::string current_keyword_;
            search_token_type current_st_;
            uint32_t current_count_;
        };
        
        std::unique_ptr<SophosClient> LargeStorageSophosClient::construct_from_json(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& json_path)
        {
            FILE* fp = fopen(json_path.c_str(), "r");
            char readBuffer[65536];
            rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
            
            JSONHandler handler(token_map_path, keyword_indexer_path);
            rapidjson::Reader reader;
            
            reader.Parse(is, handler);
            
            fclose(fp);
            
            return std::unique_ptr<LargeStorageSophosClient>(handler.client());
        }
        

        
        
        
    }
}