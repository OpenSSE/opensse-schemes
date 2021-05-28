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

#include "sophos/sophos_server_runner.hpp"

#include "sophos/sophos_server_runner_private.hpp"

#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <grpc/grpc.h>

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <fstream>
#include <thread>


namespace sse {
namespace sophos {

const char* SophosImpl::pk_file        = "tdp_pk.key";
const char* SophosImpl::pairs_map_file = "pairs.dat";

SophosImpl::SophosImpl(std::string path)
    : storage_path_(std::move(path)), async_search_(true)
{
    if (utility::is_directory(storage_path_)) {
        // try to initialize everything from this directory

        std::string pk_path        = storage_path_ + "/" + pk_file;
        std::string pairs_map_path = storage_path_ + "/" + pairs_map_file;

        if (!utility::is_file(pk_path)) {
            // error, the public key file is not there
            throw std::runtime_error("Missing public key file");
        }
        if (!utility::is_directory(pairs_map_path)) {
            // error, the token map data is not there
            throw std::runtime_error("Missing data");
        }

        std::ifstream     pk_in(pk_path.c_str());
        std::stringstream pk_buf;

        pk_buf << pk_in.rdbuf();

        server_.reset(new SophosServer(pairs_map_path, pk_buf.str()));
    } else if (utility::exists(storage_path_)) {
        // there should be nothing else than a directory at path, but we found
        // something  ...
        throw std::runtime_error(storage_path_ + ": not a directory");
    } else {
        // postpone creation upon the reception of the setup message
    }
}

grpc::Status SophosImpl::setup(__attribute__((unused))
                               grpc::ServerContext*        context,
                               const sophos::SetupMessage* message,
                               __attribute__((unused))
                               google::protobuf::Empty* e)
{
    logger::logger()->trace("Setup started");

    if (server_) {
        // problem, the server is already set up
        logger::logger()->error(
            "Info: server received a setup message but is already set up");

        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server was already set up");
    }

    // create the content directory but first check that nothing is already
    // there

    if (utility::exists(storage_path_)) {
        logger::logger()->error(
            "Error: Unable to create the server's content directory");

        return grpc::Status(grpc::ALREADY_EXISTS,
                            "Unable to create the server's content directory");
    }

    if (!utility::create_directory(storage_path_, static_cast<mode_t>(0700))) {
        logger::logger()->error(
            "Error: Unable to create the server's content directory");

        return grpc::Status(grpc::PERMISSION_DENIED,
                            "Unable to create the server's content directory");
    }

    // now, we have the directory, and we should be able to conclude the setup
    // however, the bucket_map constructor in SophosServer's constructor can
    // raise an exception, so we need to take care of it

    std::string pairs_map_path = storage_path_ + "/" + pairs_map_file;

    try {
        logger::logger()->info("Setting up server");
        server_.reset(new SophosServer(pairs_map_path, message->public_key()));
    } catch (std::exception& err) {
        logger::logger()->error("Error when setting up the server's core:\n"
                                + std::string(err.what()));

        server_.reset();
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "Unable to create the server's core. Exception: "
                                + std::string(err.what()));
    }

    // write the public key in a file
    std::string pk_path = storage_path_ + "/" + pk_file;

    std::ofstream pk_out(pk_path.c_str());
    if (!pk_out.is_open()) {
        // error

        logger::logger()->error("Error when writing the public key");

        return grpc::Status(grpc::PERMISSION_DENIED,
                            "Unable to write the public key to disk");
    }
    pk_out << message->public_key();
    pk_out.close();

    logger::logger()->trace("Successful setup");

    return grpc::Status::OK;
}

grpc::Status SophosImpl::search(grpc::ServerContext*                context,
                                const sophos::SearchRequestMessage* mes,
                                grpc::ServerWriter<sophos::SearchReply>* writer)
{
    if (async_search_) {
        return async_search(context, mes, writer);
    }
    return sync_search(context, mes, writer);
}

grpc::Status SophosImpl::sync_search(
    __attribute__((unused)) grpc::ServerContext* context,
    const sophos::SearchRequestMessage*          mes,
    grpc::ServerWriter<sophos::SearchReply>*     writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start synchronous search...");
    std::list<uint64_t> res_list;

    auto req = message_to_request(mes);

    {
        SearchBenchmark bench("Sophos synchronous search");

        res_list = server_->search_parallel(req, 2);
        bench.set_count(res_list.size());
    }

    for (auto& i : res_list) {
        sophos::SearchReply reply;
        reply.set_result(static_cast<uint64_t>(i));

        writer->Write(reply);
    }

    logger::logger()->trace("Synchronous search done");

    return grpc::Status::OK;
}


grpc::Status SophosImpl::async_search(
    __attribute__((unused)) grpc::ServerContext* context,
    const sophos::SearchRequestMessage*          mes,
    grpc::ServerWriter<sophos::SearchReply>*     writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start asynchronous search...");
    auto req = message_to_request(mes);

    std::atomic_uint res_size(0);

    std::mutex writer_lock;

    auto post_callback = [&writer, &res_size, &writer_lock](index_type i) {
        sophos::SearchReply reply;
        reply.set_result(static_cast<uint64_t>(i));

        writer_lock.lock();
        writer->Write(reply);
        writer_lock.unlock();

        res_size++;
    };

    {
        SearchBenchmark bench("Sophos asynchronous search");

        if (mes->add_count() >= 40) { // run the search algorithm in parallel
                                      // only if there are more than 2 results
            server_->search_parallel_callback(
                req, post_callback, std::thread::hardware_concurrency(), 8, 1);
        } else if (mes->add_count() >= 2) {
            server_->search_parallel_light_callback(
                req, post_callback, std::thread::hardware_concurrency());
        } else {
            server_->search_callback(req, post_callback);
        }
        bench.set_count(res_size);
    }

    logger::logger()->trace("Asynchronous search done");


    return grpc::Status::OK;
}


grpc::Status SophosImpl::insert(__attribute__((unused))
                                grpc::ServerContext*                context,
                                const sophos::UpdateRequestMessage* mes,
                                __attribute__((unused))
                                google::protobuf::Empty* e)
{
    std::unique_lock<std::mutex> lock(update_mtx_);

    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start updating");

    server_->insert(message_to_request(mes));

    logger::logger()->trace("Update completed");
    return grpc::Status::OK;
}

grpc::Status SophosImpl::bulk_insert(
    __attribute__((unused)) grpc::ServerContext*      context,
    grpc::ServerReader<sophos::UpdateRequestMessage>* reader,
    __attribute__((unused)) google::protobuf::Empty*  e)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start updating (bulk)...");

    sophos::UpdateRequestMessage mes;

    while (reader->Read(&mes)) {
        server_->insert(message_to_request(&mes));
    }

    logger::logger()->trace("Updating (bulk)... done");


    return grpc::Status::OK;
}

bool SophosImpl::search_asynchronously() const
{
    return async_search_;
}

void SophosImpl::set_search_asynchronously(bool flag)
{
    async_search_ = flag;
}

SearchRequest message_to_request(const SearchRequestMessage* mes)
{
    SearchRequest req;

    req.add_count = mes->add_count();

    assert(mes->derivation_key().size() == kDerivationKeySize);
    std::copy(mes->derivation_key().begin(),
              mes->derivation_key().begin() + kDerivationKeySize,
              req.derivation_key.begin());
    std::copy(mes->search_token().begin(),
              mes->search_token().end(),
              req.token.begin());

    return req;
}

UpdateRequest message_to_request(const UpdateRequestMessage* mes)
{
    UpdateRequest req;

    req.index = mes->index();
    std::copy(mes->update_token().begin(),
              mes->update_token().end(),
              req.token.begin());

    return req;
}

SophosServerRunner::SophosServerRunner(grpc::ServerBuilder& builder,
                                       const std::string&   server_db_path)
{
    service_.reset(new SophosImpl(server_db_path));

    builder.RegisterService(service_.get());
    server_ = builder.BuildAndStart();
}


SophosServerRunner::SophosServerRunner(const std::string& server_address,
                                       const std::string& server_db_path)
{
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    service_.reset(new SophosImpl(server_db_path));

    builder.RegisterService(service_.get());
    server_ = builder.BuildAndStart();
}

// as we forward-declare SophosImpl, we cannot use the default destructor
// NOLINTNEXTLINE(modernize-use-equals-default)
SophosServerRunner::~SophosServerRunner()
{
}

void SophosServerRunner::set_async_search(bool flag)
{
    service_->set_search_asynchronously(flag);
}

void SophosServerRunner::wait()
{
    server_->Wait();
}

void SophosServerRunner::shutdown()
{
    server_->Shutdown();
}

} // namespace sophos
} // namespace sse
