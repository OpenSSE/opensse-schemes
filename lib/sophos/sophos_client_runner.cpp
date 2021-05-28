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

#include "protos/sophos.grpc.pb.h"

#define SOPHOS_CLIENT_RUNNER_CPP
#include "sophos/sophos_client_runner.hpp"
#include "sophos/sophos_net_types.hpp"

#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
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

namespace sse {
namespace sophos {

const char* kTdpSkFile         = "tdp_sk.key";
const char* kDerivationKeyFile = "derivation_master.key";


const char* kRsaPrgKeyFile  = "rsa_prg.key";
const char* kCounterMapFile = "counters.dat";

static std::unique_ptr<SophosClient> init_client_in_directory(
    const std::string& dir_path)
{
    // try to initialize everything in this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string counter_map_path = dir_path + "/" + kCounterMapFile;
    std::string sk_path          = dir_path + "/" + kTdpSkFile;
    std::string master_key_path  = dir_path + "/" + kDerivationKeyFile;
    std::string rsa_prg_key_path = dir_path + "/" + kRsaPrgKeyFile;

    // generate the keys
    std::array<uint8_t, SophosClient::kKeySize> derivation_master_key
        = crypto::random_bytes<uint8_t, SophosClient::kKeySize>();
    std::array<uint8_t, SophosClient::kKeySize> rsa_prg_key
        = crypto::random_bytes<uint8_t, SophosClient::kKeySize>();
    crypto::TdpInverse tdp;


    // start by writing all the keys to disk

    std::ofstream sk_out(sk_path.c_str());
    if (!sk_out.is_open()) {
        throw std::runtime_error(sk_path + ": unable to write the secret key");
    }

    sk_out << tdp.private_key();
    sk_out.close();

    std::ofstream master_key_out(master_key_path.c_str());
    if (!master_key_out.is_open()) {
        throw std::runtime_error(
            master_key_path + ": unable to write the master derivation key");
    }
    master_key_out << std::string(derivation_master_key.begin(),
                                  derivation_master_key.end());
    master_key_out.close();

    std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
    if (!rsa_prg_key_out.is_open()) {
        throw std::runtime_error(rsa_prg_key_path
                                 + ": unable to write the rsa prg key");
    }
    rsa_prg_key_out << std::string(rsa_prg_key.begin(), rsa_prg_key.end());
    rsa_prg_key_out.close();


    auto c_ptr = std::unique_ptr<SophosClient>(new SophosClient(
        counter_map_path,
        tdp.private_key(),
        sse::crypto::Key<SophosClient::kKeySize>(derivation_master_key.data()),
        sse::crypto::Key<SophosClient::kKeySize>(rsa_prg_key.data())));

    return c_ptr;
}

static std::unique_ptr<SophosClient> construct_client_from_directory(
    const std::string& dir_path)
{
    // try to initialize everything from this directory
    if (!utility::is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string sk_path          = dir_path + "/" + kTdpSkFile;
    std::string master_key_path  = dir_path + "/" + kDerivationKeyFile;
    std::string counter_map_path = dir_path + "/" + kCounterMapFile;
    std::string rsa_prg_key_path = dir_path + "/" + kRsaPrgKeyFile;

    if (!utility::is_file(sk_path)) {
        // error, the secret key file is not there
        throw std::runtime_error("Missing secret key file");
    }
    if (!utility::is_file(master_key_path)) {
        // error, the derivation key file is not there
        throw std::runtime_error("Missing master derivation key file");
    }
    if (!utility::is_file(rsa_prg_key_path)) {
        // error, the rsa prg key file is not there
        throw std::runtime_error("Missing rsa prg key file");
    }
    if (!utility::is_directory(counter_map_path)) {
        // error, the token map data is not there
        throw std::runtime_error("Missing token data");
    }


    // TODO(rbost): This is a *very* ugly way to read the key files. This needs
    // a massive overhaul
    std::ifstream     sk_in(sk_path.c_str());
    std::ifstream     master_key_in(master_key_path.c_str());
    std::ifstream     rsa_prg_key_in(rsa_prg_key_path.c_str());
    std::stringstream sk_buf;
    std::stringstream master_key_buf;
    std::stringstream rsa_prg_key_buf;

    sk_buf << sk_in.rdbuf();
    master_key_buf << master_key_in.rdbuf();
    rsa_prg_key_buf << rsa_prg_key_in.rdbuf();

    std::array<uint8_t, 32> client_master_key_array;
    std::array<uint8_t, 32> client_tdp_prg_key_array;

    if (master_key_buf.str().size() != client_master_key_array.size()) {
        throw std::runtime_error(
            "Invalid master key size when constructing the Sophos client: "
            + std::to_string(master_key_buf.str().size())
            + " bytes instead of 32");
    }
    if (rsa_prg_key_buf.str().size() != client_tdp_prg_key_array.size()) {
        throw std::runtime_error(
            "Invalid PRG key size when constructing the Sophos client: "
            + std::to_string(rsa_prg_key_buf.str().size())
            + " bytes instead of 32");
    }
    auto master_key_str  = master_key_buf.str();
    auto rsa_prg_key_str = rsa_prg_key_buf.str();

    std::copy(master_key_str.begin(),
              master_key_str.end(),
              client_master_key_array.begin());
    std::copy(rsa_prg_key_str.begin(),
              rsa_prg_key_str.end(),
              client_tdp_prg_key_array.begin());


    return std::unique_ptr<SophosClient>(
        new SophosClient(counter_map_path,
                         sk_buf.str(),
                         sse::crypto::Key<SophosClient::kKeySize>(
                             client_master_key_array.data()),
                         sse::crypto::Key<SophosClient::kKeySize>(
                             client_tdp_prg_key_array.data())));
}

// De-activate clang-tidy because of a false positive in gRPC
// NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
SophosClientRunner::SophosClientRunner(
    const std::shared_ptr<grpc::Channel>& channel,
    const std::string&                    path)
{
    stub_ = sophos::Sophos::NewStub(channel);

    if (utility::is_directory(path)) {
        // try to initialize everything from this directory

        client_ = construct_client_from_directory(path);

    } else if (utility::exists(path)) {
        // there should be nothing else than a directory at path, but we found
        // something  ...
        throw std::runtime_error(path + ": not a directory");
    } else {
        // initialize a brand new Sophos client

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
}

// as we forward-declare Sophos::Stub, we cannot use the default
// destructor
// NOLINTNEXTLINE(modernize-use-equals-default)
SophosClientRunner::~SophosClientRunner()
{
    // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
}

bool SophosClientRunner::send_setup() const
{
    grpc::ClientContext     context;
    sophos::SetupMessage    message;
    google::protobuf::Empty e;

    message.set_public_key(client_->public_key());

    grpc::Status status = stub_->setup(&context, message, &e);

    if (status.ok()) {
        logger::logger()->info("Server setup succeeded.");
    } else {
        logger::logger()->error("Server setup failed: "
                                + status.error_message());
        return false;
    }

    return true;
}


const SophosClient& SophosClientRunner::client() const
{
    if (!client_) {
        throw std::logic_error("Invalid state");
    }
    return *client_;
}

std::list<uint64_t> SophosClientRunner::search(
    const std::string&                   keyword,
    const std::function<void(uint64_t)>& receive_callback) const
{
    logger::logger()->trace("Search keyword: " + keyword);

    grpc::ClientContext          context;
    sophos::SearchRequestMessage message;
    sophos::SearchReply          reply;

    message = request_to_message(client_->search_request(keyword));

    std::unique_ptr<grpc::ClientReader<sophos::SearchReply>> reader(
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
        logger::logger()->trace("Search succeeded");
    } else {
        logger::logger()->error("Search failed: " + status.error_message());
    }

    return results;
}

void SophosClientRunner::insert(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext          context;
    sophos::UpdateRequestMessage message;
    google::protobuf::Empty      e;


    if (bulk_update_state_.writer) { // an update session is running, use it
        insert_in_session(keyword, index);
    } else {
        message
            = request_to_message(client_->insertion_request(keyword, index));

        grpc::Status status = stub_->insert(&context, message, &e);

        if (status.ok()) {
            logger::logger()->trace("Update succeeded.");
        } else {
            logger::logger()->error("Update failed: " + status.error_message());
        }
    }
}

void SophosClientRunner::insert_in_session(const std::string& keyword,
                                           uint64_t           index)
{
    sophos::UpdateRequestMessage message
        = request_to_message(client_->insertion_request(keyword, index));

    if (!bulk_update_state_.is_up) {
        throw std::runtime_error("Invalid state: the update session is not up");
    }

    bulk_update_state_.mtx.lock();
    if (!bulk_update_state_.writer->Write(message)) {
        logger::logger()->error("Update session: broken stream.");
    }
    bulk_update_state_.mtx.unlock();
}

void SophosClientRunner::start_update_session()
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

void SophosClientRunner::end_update_session()
{
    if (!bulk_update_state_.writer) {
        logger::logger()->warn(
            "Invalid client state: the bulk update session is not up");
        return;
    }

    bulk_update_state_.writer->WritesDone();
    ::grpc::Status status = bulk_update_state_.writer->Finish();

    if (!status.ok()) {
        logger::logger()->error("Status not OK at the end of update sessions:\n"
                                + status.error_message());
    }

    bulk_update_state_.is_up = false;
    bulk_update_state_.context.reset();
    bulk_update_state_.writer.reset();

    logger::logger()->trace("Update session terminated.");
}


bool SophosClientRunner::load_inverted_index(const std::string& path)
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
                for (unsigned doc : documents) {
                    this->insert_in_session(keyword, doc);
                }
                counter++;

                if ((counter % 100) == 0) {
                    logger::logger()->info("Loading: {} keywords processed",
                                           counter);
                }
            };
            pool.enqueue(work, kw, docs);
        };


        parser.addCallbackList(add_list_callback);

        // De-activate clang-tidy because of a false positive in gRPC
        // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
        start_update_session();

        parser.parse();

        pool.join();
        logger::logger()->info("Loading: {} keywords processed", counter);

        end_update_session();

        return true;
    } catch (std::exception& e) {
        logger::logger()->error("Failed to load file " + path + ": "
                                + e.what());
        return false;
    }
    return false;
}

SearchRequestMessage request_to_message(const SearchRequest& req)
{
    SearchRequestMessage mes;

    mes.set_add_count(req.add_count);
    mes.set_derivation_key(req.derivation_key.data(), kDerivationKeySize);
    mes.set_search_token(req.token.data(), req.token.size());

    return mes;
}

UpdateRequestMessage request_to_message(const UpdateRequest& req)
{
    UpdateRequestMessage mes;

    mes.set_update_token(req.token.data(), req.token.size());
    mes.set_index(req.index);

    return mes;
}


} // namespace sophos
} // namespace sse
