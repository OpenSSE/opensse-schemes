//
//  large_storage_sophos_client.cpp
//  sophos
//
//  Created by Raphael Bost on 13/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "medium_storage_sophos_client.hpp"
#include "utils.hpp"
#include "logger.hpp"


#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/prettywriter.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>


#define DERIVATION_KEY "derivation"
#define TDP_KEY "tdp_pk"
#define RSA_PRG_KEY "rsa_prg"
#define TOKEN_KEY "tokens"
#define TOKEN_MAP_SIZE_KEY "map_size"


namespace sse {
    namespace sophos {
        
        
        const std::string MediumStorageSophosClient::rsa_prg_key_file__ = "rsa_prg.key";
        const std::string MediumStorageSophosClient::counter_map_file__ = "counters.dat";
        const std::string MediumStorageSophosClient::keyword_counter_file__ = "keywords.csv";

        std::unique_ptr<SophosClient> MediumStorageSophosClient::construct_from_directory(const std::string& dir_path)
        {
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            std::string keyword_index_path = dir_path + "/" + keyword_counter_file__;
            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;
            
            if (!is_file(sk_path)) {
                // error, the secret key file is not there
                throw std::runtime_error("Missing secret key file");
            }
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_file(rsa_prg_key_path)) {
                // error, the rsa prg key file is not there
                throw std::runtime_error("Missing rsa prg key file");
            }
            if (!is_directory(counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing token data");
            }
            if (!is_file(keyword_index_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing keyword indices");
            }
            
            std::ifstream sk_in(sk_path.c_str());
            std::ifstream master_key_in(master_key_path.c_str());
            std::ifstream rsa_prg_key_in(rsa_prg_key_path.c_str());
            std::stringstream sk_buf, master_key_buf, rsa_prg_key_buf;
            
            sk_buf << sk_in.rdbuf();
            master_key_buf << master_key_in.rdbuf();
            rsa_prg_key_buf << rsa_prg_key_in.rdbuf();
            
            return std::unique_ptr<SophosClient>(new  MediumStorageSophosClient(counter_map_path, keyword_index_path, sk_buf.str(), master_key_buf.str(), rsa_prg_key_buf.str()));
        }
        
        
        std::unique_ptr<SophosClient> MediumStorageSophosClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            std::string keyword_index_path = dir_path + "/" + keyword_counter_file__;

            auto c_ptr =  std::unique_ptr<SophosClient>(new MediumStorageSophosClient(counter_map_path, keyword_index_path, n_keywords));
            
            c_ptr->write_keys(dir_path);

            return c_ptr;
        }

        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size) :
        SophosClient(), rsa_prg_(), counter_map_(token_map_path, tm_setup_size)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key) :
        SophosClient(tdp_private_key, derivation_master_key), rsa_prg_(rsa_prg_key), counter_map_(token_map_path)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size) :
        SophosClient(tdp_private_key, derivation_master_key), rsa_prg_(rsa_prg_key), counter_map_(token_map_path,tm_setup_size)
        {
            load_keyword_indices(keyword_indexer_path);
            
            keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
            if (!keyword_indexer_stream_.is_open()) {
                keyword_indexer_stream_.close();
                throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
            }
        }
        
        
        MediumStorageSophosClient::~MediumStorageSophosClient()
        {
            keyword_indexer_stream_.close();
        }
        
        void MediumStorageSophosClient::load_keyword_indices(const std::string &path)
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
        
        size_t MediumStorageSophosClient::keyword_count() const
        {
            return counter_map_.size();
        }
        
        void MediumStorageSophosClient::add_keyword_index(const std::string &kw, const uint32_t index)
        {
            // CAUTION: NOT THREAD SAFE !!!
            keyword_indices_.insert(std::make_pair(kw, index));
            append_keyword_map(keyword_indexer_stream_, kw, index);
            
        }
        
        int64_t MediumStorageSophosClient::find_keyword_index(const std::string &kw) const
        {
            auto it = keyword_indices_.find(kw);
            
            if (it == keyword_indices_.end()) {
                return -1;
            }
            
            return it->second;
        }
        
        uint32_t MediumStorageSophosClient::get_keyword_index(const std::string &kw)
        {
            bool tmp;
            
            return get_keyword_index(kw, tmp);
        }
        
        uint32_t MediumStorageSophosClient::get_keyword_index(const std::string &kw, bool& is_new)
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
        
        uint32_t MediumStorageSophosClient::new_keyword_index(const std::string &kw)
        {
            // CAUTION: NOT THREAD SAFE !!!
            uint32_t c = keyword_counter_++;
            add_keyword_index(kw, c);
            
            return c;
        }
        
        SearchRequest   MediumStorageSophosClient::search_request(const std::string &keyword) const
        {
            uint32_t kw_counter;
            bool found;
            SearchRequest req;
            req.add_count = 0;
            
            int64_t kw_index = find_keyword_index(keyword);
            
            if (kw_index != -1) {
                found = counter_map_.get((uint32_t)kw_index, kw_counter);
                
                if(!found)
                {
                    logger::log(logger::ERROR) << "No matching counter found for keyword " << keyword << " (index " << kw_index << ")" << std::endl;
                }else{
                    // Now derive the original search token from the kw_index (as seed)
                    std::string seed = std::to_string(kw_index);
                    req.token = inverse_tdp().generate_array(rsa_prg_, seed);
                    req.token = inverse_tdp().invert_mult(req.token, kw_counter);
                    
                    
                    req.derivation_key = derivation_prf().prf_string(keyword);
                    req.add_count = kw_counter;
                }
            }
            return req;
        }
        
        
        UpdateRequest   MediumStorageSophosClient::update_request(const std::string &keyword, const index_type index)
        {
//            std::pair<search_token_type, uint32_t> search_pair;
            bool found = false, is_new_index = true;
            
            UpdateRequest req;
            search_token_type st;
            
            // get (and possibly construct) the keyword index
            uint32_t kw_index = get_keyword_index(keyword, is_new_index);
            std::string seed = std::to_string(kw_index);

            
            // if new_index is set to true, we will have to insert a new token in the token map
            // otherwise, search the existing token and update it
            
            if (is_new_index) {
                // derive the original token from the prg and kw_index

                st = inverse_tdp().generate_array(rsa_prg_, seed);
                
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    counter_map_.add(kw_index, 0);
                }
                logger::log(logger::DBG) << "ST0 " << logger::hex_string(st) << std::endl;
                
            }else{
                // retrieve the counter
                uint32_t kw_counter;
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    found = counter_map_.get(kw_index, kw_counter);
                }
                
                if (!found) {
                    // ERROR
                    logger::log(logger::ERROR) << "No matching counter found for keyword " << keyword << " (index " << kw_index << ")" << std::endl;
                }else{
                    // derive the original token from the prg and kw_index
                    st = inverse_tdp().generate_array(rsa_prg_, seed);

                    // RSA_SK^{-kw_counter-1}(st) to get the kw_counter+1 search token
                    st = inverse_tdp().invert_mult(st, kw_counter+1);
                    
                    logger::log(logger::DBG) << "New ST " << logger::hex_string(st) << std::endl;
                    
                    {
                        std::lock_guard<std::mutex> lock(token_map_mtx_);
                        counter_map_.at(kw_index) = kw_counter+1;
                    }
                }
            }
            
            
            std::string deriv_key = derivation_prf().prf_string(keyword);
            
            logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(deriv_key) << std::endl;
            
            
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
            
            std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
            
            req.token = derivation_prf.prf(st_string + '0');
            req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
            
            logger::log(logger::DBG) << "Update token: (" << logger::hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            
            return req;
        }
        
        std::string MediumStorageSophosClient::rsa_prg_key() const
        {
            return std::string(rsa_prg_.key().begin(), rsa_prg_.key().end());
        }

        void MediumStorageSophosClient::write_keys(const std::string& dir_path) const
        {
            SophosClient::write_keys(dir_path);

            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;

            std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
            if (!rsa_prg_key_out.is_open()) {
                throw std::runtime_error(rsa_prg_key_path + ": unable to write the rsa prg key");
            }
            
            rsa_prg_key_out << rsa_prg_key();
            rsa_prg_key_out.close();
            
        }

        std::ostream& MediumStorageSophosClient::db_to_json(std::ostream& out) const
        {
            rapidjson::OStreamWrapper ow(out);
            rapidjson::PrettyWriter<rapidjson::OStreamWrapper> writer(ow);
            
            writer.StartObject();
            
            // write the derivation key
            writer.Key(DERIVATION_KEY);
            writer.String(master_derivation_key().c_str(), (unsigned int) master_derivation_key().length());
            
            // write the private key
            writer.Key(TDP_KEY);
            writer.String(private_key().c_str(), (unsigned int) private_key().length());

            // write the RSA PRG key
            writer.Key(RSA_PRG_KEY);
            writer.String(rsa_prg_key().c_str(), (unsigned int) rsa_prg_key().length());

            // write the token array
            writer.Key(TOKEN_MAP_SIZE_KEY);
            writer.Uint64(keyword_count());
            
            // write the token array
            writer.Key(TOKEN_KEY);
            writer.StartObject();
            
            for (const auto& kw_pair : keyword_indices_) {
                writer.Key(kw_pair.first.c_str());
                writer.StartArray();

                writer.Uint(kw_pair.second);

                uint32_t kw_counter = counter_map_.at(kw_pair.second);
                
                writer.Uint64(kw_counter);
                
                writer.EndArray();
            }
            writer.EndObject();
            
            // we are done now
            writer.EndObject();
            
            
            return out;
        }
        
        std::ostream& MediumStorageSophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << counter_map_.size() << std::endl;
            out << "Load: " << counter_map_.load() << std::endl;
            out << "Overflow bucket size: " << counter_map_.overflow_size() << std::endl;
            
            return out;
        }

        
        class MediumStorageSophosClient::JSONHandler : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, JSONHandler>
        {
        public:
            JSONHandler(const std::string& counter_map_path, const std::string& keyword_indexer_path)
            : state_(kExpectStart), counter_map_path_(counter_map_path), keyword_indexer_path_(keyword_indexer_path)
            {
            }
            
            bool StartObject() {
                switch (state_) {
                    case kExpectStart:
                        state_ = kExpectParameterKey;
                        return true;
                    case kExpectTokenValuesStart:
                        state_ = kExpectKeyword;
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
                    case kExpectKeyword:
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
                        }else if(key == RSA_PRG_KEY) {
                            state_ = kExpectRSAPRGKeyValue;
                        }else if (key == TOKEN_MAP_SIZE_KEY) {
                            state_ = kExpectTokenMapSizeValue;
                        }else if (key == TOKEN_KEY) {
                            // we have to check that we parsed all the parameters
                            if( bucket_map_size_ == 0 || derivation_key_.size() == 0 || tdp_key_.size() == 0 || rsa_prg_key_.size() == 0 )
                            {
                                logger::log(logger::ERROR) << "Parsing error. At least one parameter is missing" << std::endl;
                                return false;
                            }
                            
                            // construct the client from the parameters
                            client_ = new MediumStorageSophosClient(counter_map_path_, keyword_indexer_path_, tdp_key_, derivation_key_, rsa_prg_key_, bucket_map_size_);
                            state_ = kExpectTokenValuesStart;
                        }else{
                            logger::log(logger::ERROR) << "Parsing error. Invalid key " << key  << std::endl;
                            
                            return false;
                        }
                        
                        return true;
                    case kExpectKeyword:
                        current_keyword_ = key;
                        state_ = kExpectStartList;
                        return true;
                    default:
                        logger::log(logger::ERROR) << "Parsing error. Invalid state to parse key " << key  << std::endl;
                        
                        return false;
                }
            }
            
            bool StartArray() {
                switch(state_) {
                    case kExpectStartList:
                        state_ = kExpectKeywordIndex;
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
                        client_->add_keyword_index(current_keyword_, current_index_);
                        client_->counter_map_.add(current_index_, current_count_);
                        
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
                        state_ = kExpectParameterKey;
                        return true;
                    case kExpectTDPKeyValue:
                        tdp_key_ = in;
                        state_ = kExpectParameterKey;
                       return true;
                    case kExpectRSAPRGKeyValue:
                        rsa_prg_key_ = in;
                        state_ = kExpectParameterKey;
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
                        state_ = kExpectParameterKey;
                       return true;
                    case kExpectKeywordIndex:
                        current_index_ = i;
                        state_ = kExpectKeywordCount;
                        return true;
                    case kExpectKeywordCount:
                        current_count_ = i;
                        state_ = kExpectEndList;
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
            
            MediumStorageSophosClient* client()
            {
                return client_;
            }
            
        private:
            enum State {
                kExpectStart,
                kExpectParameterKey,
                kExpectDerivationKeyValue,
                kExpectTDPKeyValue,
                kExpectRSAPRGKeyValue,
                kExpectTokenMapSizeValue,
                kExpectTokenValuesStart,
                kExpectKeyword,
                kExpectKeywordIndex,
                kExpectKeywordCount,
                kExpectStartList,
                kExpectEndList,
                kExpectEnd
            } state_;
            
            MediumStorageSophosClient* client_;
            
            const std::string& counter_map_path_;
            const std::string& keyword_indexer_path_;
            
            size_t bucket_map_size_;
            std::string derivation_key_;
            std::string tdp_key_;
            std::string rsa_prg_key_;
            
            std::string current_keyword_;
            uint32_t current_index_;
            uint32_t current_count_;
        };

        std::unique_ptr<SophosClient> MediumStorageSophosClient::construct_from_json(const std::string& dir_path, const std::string& json_path)
        {            
            FILE* fp = fopen(json_path.c_str(), "r");
            char readBuffer[65536];
            rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
            
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            std::string keyword_index_path = dir_path + "/" + keyword_counter_file__;

            JSONHandler handler(counter_map_path, keyword_index_path);
            rapidjson::Reader reader;
            
            MediumStorageSophosClient *client_ptr = NULL;
            
            bool success = reader.Parse(is, handler);
            fclose(fp);

            if(!success)
            {
                throw std::runtime_error("Failed to parse JSON at path " + json_path);
            }else{
                client_ptr = handler.client();
                client_ptr->write_keys(dir_path);
            }
            
            
            
            return std::unique_ptr<MediumStorageSophosClient>(client_ptr);
        }
        
        
        
        
        
    }
}