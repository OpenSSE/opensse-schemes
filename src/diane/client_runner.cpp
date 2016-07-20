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


#include "client_runner.hpp"

#include "types.hpp"
#include "diane/diane_client.hpp"

#include "thread_pool.hpp"
#include "utils.hpp"
#include "logger.hpp"

#include <sse/dbparser/DBParserJSON.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <fstream>

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#define MASTER_KEY_FILE "master_derivation.key"
#define KW_TOKEN_MASTER_KEY_FILE "kw_token_master.key"
#define COUNTER_MAP_FILE "counters.dat"

namespace sse {
    namespace diane {
        
        static std::unique_ptr<DianeClient> init_client_from_directory(const std::string& dir_path)
        {
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + MASTER_KEY_FILE;
            std::string kw_token_master_key_path = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;
            std::string counter_map_path = dir_path + "/" + COUNTER_MAP_FILE;
            
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_file(kw_token_master_key_path)) {
                // error, the rsa prg key file is not there
                throw std::runtime_error("Missing keyword token key file");
            }
            if (!is_directory(counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing token data");
            }
            
            std::ifstream master_key_in(master_key_path.c_str());
            std::ifstream kw_token_key_in(kw_token_master_key_path.c_str());
            std::stringstream master_key_buf, kw_token_key_buf;
            
            master_key_buf << master_key_in.rdbuf();
            kw_token_key_buf << master_key_in.rdbuf();
            
            return std::unique_ptr<DianeClient>(new  DianeClient(counter_map_path, master_key_buf.str(), kw_token_key_buf.str()));
        }
        
        std::unique_ptr<DianeClient> create_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string counter_map_path = dir_path + "/" + COUNTER_MAP_FILE;
            
            auto c_ptr =  std::unique_ptr<DianeClient>(new DianeClient(counter_map_path, n_keywords));
            
            std::string master_key_path = dir_path + "/" + MASTER_KEY_FILE;
            std::string kw_token_master_key_path = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;

            
            std::ofstream master_key_out(master_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }
            
            master_key_out << c_ptr->master_derivation_key();
            master_key_out.close();

            std::ofstream kw_token_key_out(kw_token_master_key_path.c_str());
            if (!kw_token_key_out.is_open()) {
                throw std::runtime_error(kw_token_master_key_path + ": unable to write the master derivation key");
            }
            
            kw_token_key_out << c_ptr->kw_token_master_key();
            kw_token_key_out.close();

            return c_ptr;
        }

        
        DianeClientRunner::DianeClientRunner(const std::string& address, const std::string& path, size_t setup_size, uint32_t n_keywords)
        : bulk_update_state_{0}, update_launched_count_(0), update_completed_count_(0)
        {
            std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
                                                                       grpc::InsecureChannelCredentials()));
            stub_ = Diane::NewStub(channel);
            
            if (is_directory(path)) {
                // try to initialize everything from this directory
                
                client_ = init_client_from_directory(path);
                
            }else if (exists(path)){
                // there should be nothing else than a directory at path, but we found something  ...
                throw std::runtime_error(path + ": not a directory");
            }else{
                // initialize a brand new Sophos client
                
                // start by creating a new directory
                
                if (!create_directory(path, (mode_t)0700)) {
                    throw std::runtime_error(path + ": unable to create directory");
                }
                
                client_ = create_in_directory(path,n_keywords);
                
                // send a setup message to the server
                bool success = send_setup(setup_size);
                
                if (!success) {
                    throw std::runtime_error("Unsuccessful server setup");
                }
            }
            
            // start the thread that will look for completed updates
            update_completion_thread_ = new std::thread(&DianeClientRunner::update_completion_loop, this);
        }
        
//        DianeClientRunner::DianeClientRunner(const std::string& address, const std::string& db_path, const std::string& json_path)
//        : bulk_update_state_{0}, update_launched_count_(0), update_completed_count_(0)
//        {
//            std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
//                                                                       grpc::InsecureChannelCredentials()));
//            stub_ = Diane::NewStub(channel);
//            
//            if (exists(db_path)){
//                throw std::runtime_error("File or directory already exists at " + db_path);
//            }else{
//                // initialize a brand new Sophos client
//                
//                // start by creating a new directory
//                
//                if (!create_directory(db_path, (mode_t)0700)) {
//                    throw std::runtime_error(db_path + ": unable to create directory");
//                }
//                
//                client_ = MediumStorageSophosClient::construct_from_json(db_path, json_path);
//            }
//            
//            // start the thread that will look for completed updates
//            update_completion_thread_ = new std::thread(&DianeClientRunner::update_completion_loop, this);
//        }
        
        
        DianeClientRunner::~DianeClientRunner()
        {
            update_cq_.Shutdown();
            wait_updates_completion();
            update_completion_thread_->join();
        }
        
        bool DianeClientRunner::send_setup(const size_t setup_size) const
        {
            grpc::ClientContext context;
            SetupMessage message;
            google::protobuf::Empty e;
            
            message.set_setup_size(setup_size);
            
            grpc::Status status = stub_->setup(&context, message, &e);
            
            if (status.ok()) {
                logger::log(logger::TRACE) << "Setup succeeded." << std::endl;
            } else {
                logger::log(logger::ERROR) << "Setup failed: " << std::endl;
                logger::log(logger::ERROR) << status.error_message() << std::endl;
                return false;
            }
            
            return true;
        }
        
        
        const DianeClient& DianeClientRunner::client() const
        {
            if (!client_) {
                throw std::logic_error("Invalid state");
            }
            return *client_;
        }
        
        std::list<uint64_t> DianeClientRunner::search(const std::string& keyword, std::function<void(uint64_t)> receive_callback) const
        {
            logger::log(logger::TRACE) << "Search " << keyword << std::endl;
            
            grpc::ClientContext context;
            SearchRequestMessage message;
            SearchReply reply;
            
            message = request_to_message(client_->search_request(keyword));
            
            std::unique_ptr<grpc::ClientReader<SearchReply> > reader( stub_->search(&context, message) );
            std::list<uint64_t> results;
            
            
            while (reader->Read(&reply)) {
                //        logger::log(logger::TRACE) << "New result received: "
                //        << std::dec << reply.result() << std::endl;
                results.push_back(reply.result());
                
                if (receive_callback != NULL) {
                    receive_callback(reply.result());
                }
            }
            grpc::Status status = reader->Finish();
            if (status.ok()) {
                logger::log(logger::TRACE) << "Search succeeded." << std::endl;
            } else {
                logger::log(logger::ERROR) << "Search failed:" << std::endl;
                logger::log(logger::ERROR) << status.error_message() << std::endl;
            }
            
            return results;
        }
        
        void DianeClientRunner::update(const std::string& keyword, uint64_t index)
        {
            grpc::ClientContext context;
            UpdateRequestMessage message;
            google::protobuf::Empty e;
            
            
            if (bulk_update_state_.writer) { // an update session is running, use it
                update_in_session(keyword, index);
            }else{
                message = request_to_message(client_->update_request(keyword, index));
                
                grpc::Status status = stub_->update(&context, message, &e);
                
                if (status.ok()) {
                    logger::log(logger::TRACE) << "Update succeeded." << std::endl;
                } else {
                    logger::log(logger::ERROR) << "Update failed:" << std::endl;
                    logger::log(logger::ERROR) << status.error_message() << std::endl;
                }
            }
        }
        
        void DianeClientRunner::async_update(const std::string& keyword, uint64_t index)
        {
            grpc::ClientContext context;
            UpdateRequestMessage message;
            
            
            
            if (bulk_update_state_.is_up) { // an update session is running, use it
                update_in_session(keyword, index);
            }else{
                
                message = request_to_message(client_->update_request(keyword, index));
                
                update_tag_type *tag = new update_tag_type();
                std::unique_ptr<grpc::ClientAsyncResponseReader<google::protobuf::Empty> > rpc(
                                                                                               stub_->Asyncupdate(&context, message, &update_cq_));
                
                tag->reply.reset(new google::protobuf::Empty());
                tag->status.reset(new grpc::Status());
                tag->index.reset(new size_t(update_launched_count_++));
                
                rpc->Finish(tag->reply.get(), tag->status.get(), tag);
            }
        }
        
        void DianeClientRunner::update_in_session(const std::string& keyword, uint64_t index)
        {
            UpdateRequestMessage message = request_to_message(client_->update_request(keyword, index));
            
            if(! bulk_update_state_.is_up)
            {
                throw std::runtime_error("Invalid state: the update session is not up");
            }
            
            bulk_update_state_.mtx.lock();
            if(! bulk_update_state_.writer->Write(message))
            {
                logger::log(logger::ERROR) << "Update session: broken stream." << std::endl;
            }
            bulk_update_state_.mtx.unlock();
        }
        
        void DianeClientRunner::wait_updates_completion()
        {
            stop_update_completion_thread_ = true;
            std::unique_lock<std::mutex> lock(update_completion_mtx_);
            update_completion_cv_.wait(lock, [this]{ return update_launched_count_ == update_completed_count_; });
        }
        
        void DianeClientRunner::start_update_session()
        {
            if (bulk_update_state_.writer) {
                logger::log(logger::WARNING) << "Invalid client state: the bulk update session is already up" << std::endl;
                return;
            }
            
            bulk_update_state_.context.reset(new grpc::ClientContext());
            bulk_update_state_.writer = stub_->bulk_update(bulk_update_state_.context.get(), &(bulk_update_state_.response));
            bulk_update_state_.is_up = true;
            
            logger::log(logger::TRACE) << "Update session started." << std::endl;
        }
        
        void DianeClientRunner::end_update_session()
        {
            if (!bulk_update_state_.writer) {
                logger::log(logger::WARNING) << "Invalid client state: the bulk update session is not up" << std::endl;
                return;
            }
            
            bulk_update_state_.writer->WritesDone();
            ::grpc::Status status = bulk_update_state_.writer->Finish();
            
            if (!status.ok()) {
                logger::log(logger::ERROR) << "Status not OK at the end of update sessions. Status: " << status.error_message() << std::endl;
            }
            
            bulk_update_state_.is_up = false;
            bulk_update_state_.context.reset();
            bulk_update_state_.writer.reset();
            
            logger::log(logger::TRACE) << "Update session terminated." << std::endl;
        }
        
        
        void DianeClientRunner::update_completion_loop()
        {
            update_tag_type* tag;
            bool ok = false;
            
            for (; stop_update_completion_thread_ == false ; ok = false) {
                bool r = update_cq_.Next((void**)&tag, &ok);
                if (!r) {
                    logger::log(logger::TRACE) << "Close asynchronous update loop" << std::endl;
                    return;
                }
                
                logger::log(logger::TRACE) << "Asynchronous update " << std::dec << *(tag->index) << " succeeded." << std::endl;
                delete tag;
                
                
                {
                    std::lock_guard<std::mutex> lock(update_completion_mtx_);
                    update_completed_count_++;
                    
                    if (update_launched_count_ == update_completed_count_) {
                        update_completion_cv_.notify_all();
                    }
                }
            }
        }
        
        bool DianeClientRunner::load_inverted_index(const std::string& path)
        {
            try {
                
                dbparser::DBParserJSON parser(path.c_str());
                ThreadPool pool(std::thread::hardware_concurrency());
                
                std::atomic_size_t counter(0);
                
                auto add_list_callback = [this,&pool,&counter](const string kw, const list<unsigned> docs)
                {
                    auto work = [this,&counter](const string& keyword, const list<unsigned> &documents)
                    {
                        for (unsigned doc : documents) {
                            this->async_update(keyword, doc);
                        }
                        counter++;
                        
                        if ((counter % 100) == 0) {
                            logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::flush;
                        }
                    };
                    pool.enqueue(work,kw,docs);
                    
                };
                
                parser.addCallbackList(add_list_callback);
                parser.parse();
                
                pool.join();
                logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::endl;
                
                wait_updates_completion();
                
                return true;
            } catch (std::exception& e) {
                logger::log(logger::ERROR) << "\nFailed to load file " << path << " : " << e.what() << std::endl;
                return false;
            }
            return false;
        }
        
//        bool DianeClientRunner::output_db(const std::string& out_path)
//        {
//            std::ofstream os(out_path);
//            
//            if (!os.is_open()) {
//                os.close();
//                
//                logger::log(logger::ERROR) << "Unable to create output file " << out_path << std::endl;
//                
//                return false;
//            }
//            
//            client_->db_to_json(os);
//            
//            os.close();
//            
//            return true;
//        }
        
        std::ostream& DianeClientRunner::print_stats(std::ostream& out) const
        {
            return client_->print_stats(out);
        }
        
        void DianeClientRunner::random_search() const
        {
            logger::log(logger::TRACE) << "Random Search " << std::endl;
            
            grpc::ClientContext context;
            SearchRequestMessage message;
            SearchReply reply;
            
            message = request_to_message((client_.get())->random_search_request());
            
            std::unique_ptr<grpc::ClientReader<SearchReply> > reader( stub_->search(&context, message) );
            std::list<uint64_t> results;
            
            
            while (reader->Read(&reply)) {
                logger::log(logger::TRACE) << "New result: "
                << std::dec << reply.result() << std::endl;
                results.push_back(reply.result());
            }
            grpc::Status status = reader->Finish();
            if (status.ok()) {
                logger::log(logger::TRACE) << "Search succeeded." << std::endl;
            } else {
                logger::log(logger::ERROR) << "Search failed:" << std::endl;
                logger::log(logger::ERROR) << status.error_message() << std::endl;
            }
            
        }
        
        void DianeClientRunner::search_benchmark(size_t n_bench) const
        {
            for (size_t i = 0; i < n_bench; i++) {
                logger::log(logger::INFO) << "\rBenchmark " << i+1 << std::flush;
                random_search();
            }
            logger::log(logger::INFO) << "\nBenchmarks done" << std::endl;
        }
        
        SearchRequestMessage request_to_message(const SearchRequest& req)
        {
            SearchRequestMessage mes;
            
            mes.set_add_count(req.add_count);
            
            for (auto it = req.token_list.begin(); it != req.token_list.end(); ++it) {
                SearchToken *t = mes.add_token_list();
                t->set_token(it->first.data(), it->first.size());
                t->set_depth(it->second);
            }
            mes.set_kw_token(req.kw_token.data(), req.kw_token.size());
            
            return mes;
        }
        
        UpdateRequestMessage request_to_message(const UpdateRequest& req)
        {
            UpdateRequestMessage mes;
            
            mes.set_update_token(req.token.data(), req.token.size());
            mes.set_index(req.index);
            
            return mes;
        }
        
        
    } // namespace diane
} // namespace sse