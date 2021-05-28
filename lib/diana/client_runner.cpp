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
#include "protos/diana.grpc.pb.h"

#include <sse/runners/diana/client_runner.hpp>
#include <sse/schemes/diana/diana_client.hpp>
#include <sse/schemes/diana/types.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/thread_pool.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/dbparser/json/DBParserJSON.h>

#include <grpc/grpc.h>

#include <grpcpp/grpcpp.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>

#define MASTER_KEY_FILE "master_derivation.key"
#define KW_TOKEN_MASTER_KEY_FILE "kw_token_master.key"
#define WRAPPING_KEY_FILE "wrapping.key"
#define COUNTER_MAP_FILE "counters.dat"

namespace sse {
namespace diana {

using DC = DianaClient<DianaClientRunner::index_type>;

static std::unique_ptr<DC> construct_client_from_directory(
    const std::string&                     dir_path,
    std::unique_ptr<sse::crypto::Wrapper>& wrapper)
{
    // try to initialize everything from this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string master_key_path = dir_path + "/" + MASTER_KEY_FILE;
    std::string kw_token_master_key_path
        = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;
    std::string wrapping_key_path = dir_path + "/" + WRAPPING_KEY_FILE;
    std::string counter_map_path  = dir_path + "/" + COUNTER_MAP_FILE;

    if (!utility::is_file(master_key_path)) {
        // error, the derivation key file is not there
        throw std::runtime_error("Missing master derivation key file");
    }
    if (!utility::is_file(kw_token_master_key_path)) {
        // error, the rsa prg key file is not there
        throw std::runtime_error("Missing keyword token key file");
    }
    if (!utility::is_file(wrapping_key_path)) {
        // error, the wrapping key file is not there
        throw std::runtime_error("Missing wrapping key file");
    }
    if (!utility::is_directory(counter_map_path)) {
        // error, the token map data is not there
        throw std::runtime_error("Missing token data");
    }

    // TODO(rbost): This is a *very* ugly way to read the key files. This needs
    // a massive overhaul
    std::ifstream master_key_in(master_key_path.c_str());
    std::ifstream kw_token_key_in(kw_token_master_key_path.c_str());
    std::ifstream wrapping_key_in(wrapping_key_path.c_str());


    std::stringstream master_key_buf;
    std::stringstream kw_token_key_buf;
    std::stringstream wrapping_key_buf;

    master_key_buf << master_key_in.rdbuf();
    kw_token_key_buf << kw_token_key_in.rdbuf();
    wrapping_key_buf << wrapping_key_in.rdbuf();

    std::array<uint8_t, DC::kKeySize> client_master_key_array;
    std::array<uint8_t, DC::kKeySize> client_kw_token_key_array;
    std::array<uint8_t, DC::kKeySize> client_wrapping_key_array;


    if (master_key_buf.str().size() != client_master_key_array.size()) {
        throw std::runtime_error(
            "Invalid master key size when constructing the Diana client: "
            + std::to_string(master_key_buf.str().size())
            + " bytes instead of 32");
    }
    if (kw_token_key_buf.str().size() != client_kw_token_key_array.size()) {
        throw std::runtime_error("Invalid keyword token key size when "
                                 "constructing the Diana client: "
                                 + std::to_string(kw_token_key_buf.str().size())
                                 + " bytes instead of 32");
    }
    if (wrapping_key_buf.str().size() != client_wrapping_key_array.size()) {
        throw std::runtime_error("Invalid wrapping key size when "
                                 "constructing the Diana client: "
                                 + std::to_string(wrapping_key_buf.str().size())
                                 + " bytes instead of 32");
    }

    auto master_key_str   = master_key_buf.str();
    auto kw_token_key_str = kw_token_key_buf.str();
    auto wrapping_key_str = wrapping_key_buf.str();

    std::copy(master_key_str.begin(),
              master_key_str.end(),
              client_master_key_array.begin());
    std::copy(kw_token_key_str.begin(),
              kw_token_key_str.end(),
              client_kw_token_key_array.begin());
    std::copy(wrapping_key_str.begin(),
              wrapping_key_str.end(),
              client_wrapping_key_array.begin());

    wrapper.reset(new sse::crypto::Wrapper(
        sse::crypto::Key<DC::kKeySize>(client_wrapping_key_array.data())));

    return std::unique_ptr<DC>(new DC(
        counter_map_path,
        sse::crypto::Key<DC::kKeySize>(client_master_key_array.data()),
        sse::crypto::Key<DC::kKeySize>(client_kw_token_key_array.data())));
}

std::unique_ptr<DC> init_client_in_directory(
    const std::string&                              dir_path,
    std::array<uint8_t, crypto::Wrapper::kKeySize>& wrapping_key)
{
    // try to initialize everything in this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string counter_map_path  = dir_path + "/" + COUNTER_MAP_FILE;
    std::string master_key_path   = dir_path + "/" + MASTER_KEY_FILE;
    std::string wrapping_key_path = dir_path + "/" + WRAPPING_KEY_FILE;
    std::string kw_token_master_key_path
        = dir_path + "/" + KW_TOKEN_MASTER_KEY_FILE;


    // generate the keys
    std::array<uint8_t, DC::kKeySize> master_derivation_key
        = sse::crypto::random_bytes<uint8_t, DC::kKeySize>();
    std::array<uint8_t, DC::kKeySize> kw_token_master_key
        = sse::crypto::random_bytes<uint8_t, DC::kKeySize>();
    // no need to define a new variable for the wrapping key: the wrapping_key
    // variable will be output here
    wrapping_key = sse::crypto::random_bytes<uint8_t, DC::kKeySize>();

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

    std::ofstream wrapping_key_out(wrapping_key_path.c_str());
    if (!wrapping_key_out.is_open()) {
        throw std::runtime_error(
            wrapping_key_path + ": unable to write the master derivation key");
    }

    wrapping_key_out << std::string(wrapping_key.begin(), wrapping_key.end());
    wrapping_key_out.close();

    return std::unique_ptr<DC>(
        new DC(counter_map_path,
               sse::crypto::Key<DC::kKeySize>(master_derivation_key.data()),
               sse::crypto::Key<DC::kKeySize>(kw_token_master_key.data())));
}

// NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
DianaClientRunner::DianaClientRunner(
    const std::shared_ptr<grpc::Channel>& channel,
    const std::string&                    path)
    : stub_(Diana::NewStub(channel))
{
    if (utility::is_directory(path)) {
        // try to initialize everything from this directory

        client_ = construct_client_from_directory(path, token_wrapper_);

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

        std::array<uint8_t, crypto::Wrapper::kKeySize> wrapper_key;
        client_ = init_client_in_directory(path, wrapper_key);

        // send a setup message to the server
        bool success = send_setup(wrapper_key);

        token_wrapper_.reset(new crypto::Wrapper(
            crypto::Key<crypto::Wrapper::kKeySize>(wrapper_key.data())));

        if (!success) {
            throw std::runtime_error("Unsuccessful server setup");
        }
    }
}

// as we forward-declare Diana::Stub, we cannot use the default destructor
// NOLINTNEXTLINE(modernize-use-equals-default)
DianaClientRunner::~DianaClientRunner()
{
    // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
}

bool DianaClientRunner::send_setup(
    const std::array<uint8_t, crypto::Wrapper::kKeySize>& wrapping_key) const
{
    grpc::ClientContext     context;
    SetupMessage            message;
    google::protobuf::Empty e;

    message.set_wrapping_key(wrapping_key.data(), wrapping_key.size());

    grpc::Status status = stub_->setup(&context, message, &e);

    if (status.ok()) {
        logger::logger()->info("Server setup succeeded.");
    } else {
        logger::logger()->error("Server setup failed: \n"
                                + status.error_message());
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
    logger::logger()->trace("Searching keyword: " + keyword);

    grpc::ClientContext  context;
    SearchRequestMessage message;
    SearchReply          reply;

    message
        = request_to_message(token_wrapper_, client_->search_request(keyword));

    if (message.add_count() == 0) {
        return {};
    }

    std::unique_ptr<grpc::ClientReader<SearchReply>> reader(
        stub_->search(&context, message));
    std::list<uint64_t> results;


    while (reader->Read(&reply)) {
        results.push_back(reply.result());

        if (receive_callback != nullptr) {
            receive_callback(reply.result());
        }
    }
    grpc::Status status = reader->Finish();
    if (status.ok()) {
        logger::logger()->trace("Search succeeded.");
    } else {
        logger::logger()->error("Search failed: \n" + status.error_message());
    }

    return results;
}

void DianaClientRunner::insert(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext     context;
    UpdateRequestMessage    message;
    google::protobuf::Empty e;


    if (bulk_update_state_.writer) { // an update session is running, use it
        insert_in_session(keyword, index);
    } else {
        message
            = request_to_message(client_->insertion_request(keyword, index));

        grpc::Status status = stub_->insert(&context, message, &e);

        if (status.ok()) {
            logger::logger()->trace("Update succeeded.");
        } else {
            logger::logger()->error("Update failed:\n"
                                    + status.error_message());
        }
    }
}

void DianaClientRunner::insert_in_session(const std::string& keyword,
                                          uint64_t           index)
{
    UpdateRequestMessage message
        = request_to_message(client_->insertion_request(keyword, index));

    if (!bulk_update_state_.is_up) {
        throw std::runtime_error("Invalid state: the update session is not up");
    }

    bulk_update_state_.mtx.lock();
    if (!bulk_update_state_.writer->Write(message)) {
        logger::logger()->error("Update session stopped: broken stream.");
    }
    bulk_update_state_.mtx.unlock();
}


void DianaClientRunner::insert_in_session(
    const std::list<std::pair<std::string, uint64_t>>& update_list)
{
    if (!bulk_update_state_.is_up) {
        throw std::runtime_error("Invalid state: the update session is not up");
    }

    std::list<UpdateRequest<DianaClientRunner::index_type>> message_list
        = client_->bulk_insertion_request(update_list);

    bulk_update_state_.mtx.lock();

    bool success = std::all_of(
        message_list.begin(),
        message_list.end(),
        [this](const UpdateRequest<DianaClientRunner::index_type>& req) {
            return this->bulk_update_state_.writer->Write(
                request_to_message(req));
        });

    if (!success) {
        logger::logger()->error("Update session stopped: broken stream.");
    }

    bulk_update_state_.mtx.unlock();
}

void DianaClientRunner::start_update_session()
{
    if (bulk_update_state_.writer) {
        logger::logger()->warn(
            "Invalid client state: the bulk update session is already up");
        return;
    }

    bulk_update_state_.context.reset(new grpc::ClientContext());
    bulk_update_state_.writer = stub_->bulk_insert(
        bulk_update_state_.context.get(), &(bulk_update_state_.response));
    bulk_update_state_.is_up = true;

    logger::logger()->trace("Update session started.");
}

void DianaClientRunner::end_update_session()
{
    if (!bulk_update_state_.writer) {
        logger::logger()->warn(
            "Invalid client state: the bulk update session is not up");
        return;
    }

    bulk_update_state_.writer->WritesDone();
    ::grpc::Status status = bulk_update_state_.writer->Finish();

    if (!status.ok()) {
        logger::logger()->error(
            "Status not OK at the end of update sessions. Status: \n"
            + status.error_message());
    }

    bulk_update_state_.is_up = false;
    bulk_update_state_.context.reset();
    bulk_update_state_.writer.reset();

    logger::logger()->trace("Update session terminated.");
}


bool DianaClientRunner::load_inverted_index(const std::string& path)
{
    try {
        dbparser::DBParserJSON parser(path.c_str());
        ThreadPool             pool(std::thread::hardware_concurrency());

        std::atomic_size_t counter(0);

        auto add_list_callback = [this, &pool, &counter](
                                     const std::string&         kw,
                                     const std::list<unsigned>& docs) {
            auto work = [this, &counter](const std::string&         keyword,
                                         const std::list<unsigned>& documents) {
                std::list<std::pair<std::string, uint64_t>> update_list;
                update_list.resize(documents.size());

                std::transform(documents.begin(),
                               documents.end(),
                               update_list.begin(),
                               [&keyword](unsigned doc) {
                                   return std::pair<std::string, uint64_t>(
                                       std::string(keyword), doc);
                               });
                this->insert_in_session(update_list);
                counter++;

                if ((counter % 100) == 0) {
                    logger::logger()->info("Loading: {} keywords processed",
                                           counter);
                }
            };
            pool.enqueue(work, kw, docs);
        };

        parser.addCallbackList(add_list_callback);

        // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
        start_update_session();

        parser.parse();

        pool.join();
        logger::logger()->info("Loading: {} keywords processed", counter);

        end_update_session();

        return true;
    } catch (std::exception& e) {
        logger::logger()->error("Failed to load file " + path + ": \n"
                                + e.what());
        return false;
    }
    return false;
}

SearchRequestMessage request_to_message(
    const std::unique_ptr<crypto::Wrapper>& wrapper,
    const SearchRequest&                    req)
{
    SearchRequestMessage mes;

    mes.set_add_count(req.add_count);

    auto buffer = wrapper->wrap(req.constrained_rcprf);

    // for (const auto& it : req.token_list) {
    //     SearchToken* t = mes.add_token_list();
    //     t->set_token(it.first.data(), it.first.size());
    //     t->set_depth(it.second);
    // }
    mes.set_constrained_rcprf_rep(buffer.data(), buffer.size());

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
