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

#define DIANA_CLIENT_RUNNER_CPP
#include "diana.grpc.pb.h"

#include <sse/runners/diana/client_runner.hpp>
#include <sse/schemes/diana/diana_client.hpp>
#include <sse/schemes/diana/types.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/thread_pool.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/dbparser/json/DBParserJSON.h>

#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>

#include <chrono>

#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>

#define MASTER_KEY_FILE "master_derivation.key"
#define KW_TOKEN_MASTER_KEY_FILE "kw_token_master.key"
#define COUNTER_MAP_FILE "counters.dat"

namespace sse {
namespace diana {

using DC = DianaClient<DianaClientRunner::index_type>;

static std::unique_ptr<DC> construct_client_from_directory(
    const std::string& dir_path)
{
    // try to initialize everything from this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string master_key_path = dir_path + "/" + MASTER_KEY_FILE;
    std::string kw_token_master_key_path
        = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;
    std::string counter_map_path = dir_path + "/" + COUNTER_MAP_FILE;

    if (!utility::is_file(master_key_path)) {
        // error, the derivation key file is not there
        throw std::runtime_error("Missing master derivation key file");
    }
    if (!utility::is_file(kw_token_master_key_path)) {
        // error, the rsa prg key file is not there
        throw std::runtime_error("Missing keyword token key file");
    }
    if (!utility::is_directory(counter_map_path)) {
        // error, the token map data is not there
        throw std::runtime_error("Missing token data");
    }

    std::ifstream     master_key_in(master_key_path.c_str());
    std::stringstream master_key_buf, kw_token_key_buf;

    master_key_buf << master_key_in.rdbuf();
    kw_token_key_buf << master_key_in.rdbuf();

    std::array<uint8_t, 32> client_master_key_array, client_kw_token_key_array;

    assert(master_key_buf.str().size() == client_master_key_array.size());
    assert(kw_token_key_buf.str().size() == client_kw_token_key_array.size());

    std::copy(master_key_buf.str().begin(),
              master_key_buf.str().end(),
              client_master_key_array.begin());
    std::copy(kw_token_key_buf.str().begin(),
              kw_token_key_buf.str().end(),
              client_kw_token_key_array.begin());

    return std::unique_ptr<DC>(new DC(
        counter_map_path,
        sse::crypto::Key<DC::kKeySize>(client_master_key_array.data()),
        sse::crypto::Key<DC::kKeySize>(client_kw_token_key_array.data())));
}

std::unique_ptr<DC> init_client_in_directory(const std::string& dir_path)
{
    // try to initialize everything in this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string counter_map_path = dir_path + "/" + COUNTER_MAP_FILE;
    std::string master_key_path  = dir_path + "/" + MASTER_KEY_FILE;
    std::string kw_token_master_key_path
        = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;


    // generate the keys
    std::array<uint8_t, DC::kKeySize> master_derivation_key
        = sse::crypto::random_bytes<uint8_t, DC::kKeySize>();
    std::array<uint8_t, DC::kKeySize> kw_token_master_key
        = sse::crypto::random_bytes<uint8_t, DC::kKeySize>();

    std::ofstream master_key_out(master_key_path.c_str());
    if (!master_key_out.is_open()) {
        throw std::runtime_error(
            master_key_path + ": unable to write the master derivation key");
    }

    master_key_out << std::string(master_derivation_key.begin(),
                                  master_derivation_key.end());
    master_key_out.close();

    std::ofstream kw_token_key_out(kw_token_master_key_path.c_str());
    if (!kw_token_key_out.is_open()) {
        throw std::runtime_error(
            kw_token_master_key_path
            + ": unable to write the master derivation key");
    }

    kw_token_key_out << std::string(kw_token_master_key.begin(),
                                    kw_token_master_key.end());
    kw_token_key_out.close();

    return std::unique_ptr<DC>(
        new DC(counter_map_path,
               sse::crypto::Key<DC::kKeySize>(master_derivation_key.data()),
               sse::crypto::Key<DC::kKeySize>(kw_token_master_key.data())));
}

// NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
DianaClientRunner::DianaClientRunner(const std::string& address,
                                     const std::string& path)
    : update_launched_count_(0), update_completed_count_(0)
{
    std::shared_ptr<grpc::Channel> channel(
        grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    stub_ = Diana::NewStub(channel);

    if (utility::is_directory(path)) {
        // try to initialize everything from this directory

        client_ = construct_client_from_directory(path);

    } else if (utility::exists(path)) {
        // there should be nothing else than a directory at path, but we found
        // something  ...
        throw std::runtime_error(path + ": not a directory");
    } else {
        // initialize a brand new Diana client

        // start by creating a new directory

        if (!utility::create_directory(path, static_cast<mode_t>(0700))) {
            throw std::runtime_error(path + ": unable to create directory");
        }

        client_ = init_client_in_directory(path);

        // send a setup message to the server
        bool success = send_setup();

        if (!success) {
            throw std::runtime_error("Unsuccessful server setup");
        }
    }

    // start the thread that will look for completed updates
    update_completion_thread_
        = new std::thread(&DianaClientRunner::update_completion_loop, this);
}

DianaClientRunner::~DianaClientRunner()
{
    update_cq_.Shutdown();
    wait_updates_completion();
    update_completion_thread_->join();
}

bool DianaClientRunner::send_setup() const
{
    grpc::ClientContext     context;
    SetupMessage            message;
    google::protobuf::Empty e;

    grpc::Status status = stub_->setup(&context, message, &e);

    if (status.ok()) {
        logger::log(logger::LoggerSeverity::TRACE)
            << "Setup succeeded." << std::endl;
    } else {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Setup failed: " << std::endl;
        logger::log(logger::LoggerSeverity::ERROR)
            << status.error_message() << std::endl;
        return false;
    }

    return true;
}


const DC& DianaClientRunner::client() const
{
    if (!client_) {
        throw std::logic_error("Invalid state");
    }
    return *client_;
}

std::list<uint64_t> DianaClientRunner::search(
    const std::string&                   keyword,
    const std::function<void(uint64_t)>& receive_callback) const
{
    logger::log(logger::LoggerSeverity::TRACE)
        << "Search " << keyword << std::endl;

    grpc::ClientContext  context;
    SearchRequestMessage message;
    SearchReply          reply;

    message = request_to_message(client_->search_request(keyword));

    if (message.add_count() == 0) {
        return {};
    }

    std::unique_ptr<grpc::ClientReader<SearchReply>> reader(
        stub_->search(&context, message));
    std::list<uint64_t> results;


    while (reader->Read(&reply)) {
        //        logger::log(logger::LoggerSeverity::TRACE) << "New result
        //        received: "
        //        << std::dec << reply.result() << std::endl;
        results.push_back(reply.result());

        if (receive_callback != nullptr) {
            receive_callback(reply.result());
        }
    }
    grpc::Status status = reader->Finish();
    if (status.ok()) {
        logger::log(logger::LoggerSeverity::TRACE)
            << "Search succeeded." << std::endl;
    } else {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Search failed:" << std::endl;
        logger::log(logger::LoggerSeverity::ERROR)
            << status.error_message() << std::endl;
    }

    return results;
}

void DianaClientRunner::update(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext     context;
    UpdateRequestMessage    message;
    google::protobuf::Empty e;


    if (bulk_update_state_.writer) { // an update session is running, use it
        update_in_session(keyword, index);
    } else {
        message = request_to_message(client_->update_request(keyword, index));

        grpc::Status status = stub_->update(&context, message, &e);

        if (status.ok()) {
            logger::log(logger::LoggerSeverity::TRACE)
                << "Update succeeded." << std::endl;
        } else {
            logger::log(logger::LoggerSeverity::ERROR)
                << "Update failed:" << std::endl;
            logger::log(logger::LoggerSeverity::ERROR)
                << status.error_message() << std::endl;
        }
    }
}

void DianaClientRunner::async_update(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext  context;
    UpdateRequestMessage message;


    if (bulk_update_state_.is_up) { // an update session is running, use it
        update_in_session(keyword, index);
    } else {
        message = request_to_message(client_->update_request(keyword, index));

        update_tag_type* tag = new update_tag_type();
        std::unique_ptr<
            grpc::ClientAsyncResponseReader<google::protobuf::Empty>>
            rpc(stub_->Asyncupdate(&context, message, &update_cq_));

        tag->reply.reset(new google::protobuf::Empty());
        tag->status.reset(new grpc::Status());
        tag->index.reset(new size_t(update_launched_count_++));

        rpc->Finish(tag->reply.get(), tag->status.get(), tag);
    }
}

void DianaClientRunner::async_update(
    const std::list<std::pair<std::string, uint64_t>>& update_list)
{
    if (bulk_update_state_.is_up) { // an update session is running, use it
        update_in_session(update_list);
    } else {
        grpc::ClientContext  context;
        UpdateRequestMessage message;


        for (const auto& it : update_list) {
            message = request_to_message(
                client_->update_request(it.first, it.second));

            update_tag_type* tag = new update_tag_type();
            std::unique_ptr<
                grpc::ClientAsyncResponseReader<google::protobuf::Empty>>
                rpc(stub_->Asyncupdate(&context, message, &update_cq_));

            tag->reply.reset(new google::protobuf::Empty());
            tag->status.reset(new grpc::Status());
            tag->index.reset(new size_t(update_launched_count_++));

            rpc->Finish(tag->reply.get(), tag->status.get(), tag);
        }
    }
}

void DianaClientRunner::update_in_session(const std::string& keyword,
                                          uint64_t           index)
{
    UpdateRequestMessage message
        = request_to_message(client_->update_request(keyword, index));

    if (!bulk_update_state_.is_up) {
        throw std::runtime_error("Invalid state: the update session is not up");
    }

    bulk_update_state_.mtx.lock();
    if (!bulk_update_state_.writer->Write(message)) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Update session: broken stream." << std::endl;
    }
    bulk_update_state_.mtx.unlock();
}


void DianaClientRunner::update_in_session(
    const std::list<std::pair<std::string, uint64_t>>& update_list)
{
    if (!bulk_update_state_.is_up) {
        throw std::runtime_error("Invalid state: the update session is not up");
    }


    //            std::list<UpdateRequestMessage> message_list;

    //            for(auto it = update_list.begin(); it != update_list.end();
    //            ++it)
    //            {
    //                message_list.push_back(request_to_message(client_->update_request(it->first,
    //                it->second)));
    //            }

    std::list<UpdateRequest<DianaClientRunner::index_type>> message_list
        = client_->bulk_update_request(update_list);

    bulk_update_state_.mtx.lock();

    for (auto& it : message_list) {
        if (!bulk_update_state_.writer->Write(request_to_message(it))) {
            logger::log(logger::LoggerSeverity::ERROR)
                << "Update session: broken stream." << std::endl;
            break;
        }
    }
    bulk_update_state_.mtx.unlock();
}

void DianaClientRunner::wait_updates_completion()
{
    stop_update_completion_thread_ = true;
    std::unique_lock<std::mutex> lock(update_completion_mtx_);
    update_completion_cv_.wait(lock, [this] {
        return update_launched_count_ == update_completed_count_;
    });
}

void DianaClientRunner::start_update_session()
{
    if (bulk_update_state_.writer) {
        logger::log(logger::LoggerSeverity::WARNING)
            << "Invalid client state: the bulk update session is already up"
            << std::endl;
        return;
    }

    bulk_update_state_.context.reset(new grpc::ClientContext());
    bulk_update_state_.writer = stub_->bulk_update(
        bulk_update_state_.context.get(), &(bulk_update_state_.response));
    bulk_update_state_.is_up = true;

    logger::log(logger::LoggerSeverity::TRACE)
        << "Update session started." << std::endl;
}

void DianaClientRunner::end_update_session()
{
    if (!bulk_update_state_.writer) {
        logger::log(logger::LoggerSeverity::WARNING)
            << "Invalid client state: the bulk update session is not up"
            << std::endl;
        return;
    }

    bulk_update_state_.writer->WritesDone();
    ::grpc::Status status = bulk_update_state_.writer->Finish();

    if (!status.ok()) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Status not OK at the end of update sessions. Status: "
            << status.error_message() << std::endl;
    }

    bulk_update_state_.is_up = false;
    bulk_update_state_.context.reset();
    bulk_update_state_.writer.reset();

    logger::log(logger::LoggerSeverity::TRACE)
        << "Update session terminated." << std::endl;
}


void DianaClientRunner::update_completion_loop()
{
    update_tag_type* tag;
    bool             ok = false;

    for (; !stop_update_completion_thread_; ok = false) {
        bool r = update_cq_.Next(reinterpret_cast<void**>(&tag), &ok);
        if (!r) {
            logger::log(logger::LoggerSeverity::TRACE)
                << "Close asynchronous update loop" << std::endl;
            return;
        }

        logger::log(logger::LoggerSeverity::TRACE)
            << "Asynchronous update " << std::dec << *(tag->index)
            << " succeeded." << std::endl;
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

bool DianaClientRunner::load_inverted_index(const std::string& path)
{
    try {
        dbparser::DBParserJSON parser(path.c_str());
        ThreadPool             pool(std::thread::hardware_concurrency());

        std::atomic_size_t counter(0);

        auto add_list_callback
            = [this, &pool, &counter](const std::string         kw,
                                      const std::list<unsigned> docs) {
                  auto work
                      = [this, &counter](const std::string&         keyword,
                                         const std::list<unsigned>& documents) {
                            for (unsigned doc : documents) {
                                this->async_update(keyword, doc);
                            }
                            counter++;

                            if ((counter % 100) == 0) {
                                logger::log(sse::logger::LoggerSeverity::INFO)
                                    << "\rLoading: " << counter
                                    << " keywords processed" << std::flush;
                            }
                        };
                  pool.enqueue(work, kw, docs);
              };

        parser.addCallbackList(add_list_callback);

        // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
        start_update_session();

        parser.parse();

        pool.join();
        logger::log(sse::logger::LoggerSeverity::INFO)
            << "\rLoading: " << counter << " keywords processed" << std::endl;

        wait_updates_completion();

        end_update_session();

        return true;
    } catch (std::exception& e) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "\nFailed to load file " << path << " : " << e.what()
            << std::endl;
        return false;
    }
    return false;
}

//        bool DianaClientRunner::output_db(const std::string& out_path)
//        {
//            std::ofstream os(out_path);
//
//            if (!os.is_open()) {
//                os.close();
//
//                logger::log(logger::LoggerSeverity::ERROR) << "Unable to
//                create output file "
//                << out_path << std::endl;
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

std::ostream& DianaClientRunner::print_stats(std::ostream& out) const
{
    return client_->print_stats(out);
}

//        void DianaClientRunner::random_search() const
//        {
//            logger::log(logger::LoggerSeverity::TRACE) << "Random Search " <<
//            std::endl;
//
//            grpc::ClientContext context;
//            SearchRequestMessage message;
//            SearchReply reply;
//
//            message =
//            request_to_message((client_.get())->random_search_request());
//
//            std::unique_ptr<grpc::ClientReader<SearchReply> > reader(
//            stub_->search(&context, message) ); std::list<uint64_t> results;
//
//
//            while (reader->Read(&reply)) {
//                logger::log(logger::LoggerSeverity::TRACE) << "New result: "
//                << std::dec << reply.result() << std::endl;
//                results.push_back(reply.result());
//            }
//            grpc::Status status = reader->Finish();
//            if (status.ok()) {
//                logger::log(logger::LoggerSeverity::TRACE) << "Search
//                succeeded." << std::endl;
//            } else {
//                logger::log(logger::LoggerSeverity::ERROR) << "Search failed:"
//                << std::endl; logger::log(logger::LoggerSeverity::ERROR) <<
//                status.error_message() << std::endl;
//            }
//
//        }

//        void DianaClientRunner::search_benchmark(size_t n_bench) const
//        {
//            for (size_t i = 0; i < n_bench; i++) {
//                logger::log(logger::LoggerSeverity::INFO) << "\rBenchmark " <<
//                i+1 << std::flush; random_search();
//            }
//            logger::log(logger::LoggerSeverity::INFO) << "\nBenchmarks done"
//            << std::endl;
//        }

SearchRequestMessage request_to_message(const SearchRequest& req)
{
    SearchRequestMessage mes;

    mes.set_add_count(req.add_count);

    for (const auto& it : req.token_list) {
        SearchToken* t = mes.add_token_list();
        t->set_token(it.first.data(), it.first.size());
        t->set_depth(it.second);
    }
    mes.set_kw_token(req.kw_token.data(), req.kw_token.size());

    return mes;
}

UpdateRequestMessage request_to_message(
    const UpdateRequest<DianaClientRunner::index_type>& req)
{
    UpdateRequestMessage mes;

    mes.set_update_token(req.token.data(), req.token.size());
    mes.set_index(req.index);

    return mes;
}


} // namespace diana
} // namespace sse
