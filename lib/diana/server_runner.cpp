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

#include "diana/server_runner.hpp"

#include "diana/server_runner_private.hpp"

#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/wrapper.hpp>

#include <grpc/grpc.h>

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <fstream>
#include <thread>
#include <utility>


namespace sse {
namespace diana {

const char* DianaImpl::pairs_map_file    = "pairs.dat";
const char* DianaImpl::wrapping_key_file = "wrapping.key";

DianaImpl::DianaImpl(std::string path)
    : storage_path_(std::move(path)), async_search_(true)
{
    if (utility::is_directory(storage_path_)) {
        // try to initialize everything from this directory

        std::string pairs_map_path    = storage_path_ + "/" + pairs_map_file;
        std::string wrapping_key_path = storage_path_ + "/" + wrapping_key_file;

        if (!utility::is_file(wrapping_key_path)) {
            // error, the wrapping key file is not there
            throw std::runtime_error("Missing wrapping key file");
        }
        if (!utility::is_directory(pairs_map_path)) {
            // error, the token map data is not there
            throw std::runtime_error("Missing data");
        }

        std::ifstream     wrapping_key_in(wrapping_key_path.c_str());
        std::stringstream wrapping_key_buf;
        std::array<uint8_t, crypto::Wrapper::kKeySize> wrapping_key_array;

        wrapping_key_buf << wrapping_key_in.rdbuf();

        auto wrapping_key_str = wrapping_key_buf.str();

        if (wrapping_key_str.size() != wrapping_key_array.size()) {
            throw std::runtime_error(
                "Invalid wrapping key size when "
                "constructing the Diana server: "
                + std::to_string(wrapping_key_buf.str().size())
                + " bytes instead of 32");
        }
        std::copy(wrapping_key_str.begin(),
                  wrapping_key_str.end(),
                  wrapping_key_array.begin());
        token_wrapper_.reset(new sse::crypto::Wrapper(
            sse::crypto::Key<crypto::Wrapper::kKeySize>(
                wrapping_key_array.data())));

        server_.reset(new DianaServer<index_type>(pairs_map_path));
    } else if (utility::exists(storage_path_)) {
        // there should be nothing else than a directory at path, but we found
        // something  ...
        throw std::runtime_error(storage_path_ + ": not a directory");
    } else {
        // postpone creation upon the reception of the setup message
    }
}

DianaImpl::~DianaImpl()
{
    flush_server_storage();
}

grpc::Status DianaImpl::setup(__attribute__((unused))
                              grpc::ServerContext* context,
                              const SetupMessage*  message,
                              __attribute__((unused))
                              google::protobuf::Empty* e)
{
    logger::logger()->trace("Start server setup");

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
        logger::logger()->info("Setting up ...");
        server_.reset(new DianaServer<index_type>(pairs_map_path));
    } catch (std::exception& err) {
        logger::logger()->error("Error when setting up the server's core: \n"
                                + std::string(err.what()));

        server_.reset();
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "Unable to create the server's core.");
    }


    // write the wrapping key in a file
    std::string wrapping_key_path = storage_path_ + "/" + wrapping_key_file;

    std::ofstream wrapping_key_out(wrapping_key_path.c_str());
    if (!wrapping_key_out.is_open()) {
        // error

        logger::logger()->error("Error when writing the wrapping key");

        return grpc::Status(grpc::PERMISSION_DENIED,
                            "Unable to write the wrapping key to disk");
    }

    if (message->wrapping_key().size() != crypto::Wrapper::kKeySize) {
        logger::logger()->error("Invalid wrapping key size");

        return grpc::Status(grpc::INVALID_ARGUMENT,
                            "Invalid transmitted wrapping key size");
    }

    wrapping_key_out << message->wrapping_key();
    wrapping_key_out.close();

    std::array<uint8_t, crypto::Wrapper::kKeySize> wrapping_key;
    std::copy(message->wrapping_key().begin(),
              message->wrapping_key().end(),
              wrapping_key.begin());

    token_wrapper_.reset(new crypto::Wrapper(
        crypto::Key<crypto::Wrapper::kKeySize>(wrapping_key.data())));

    logger::logger()->trace("Successful setup");

    return grpc::Status::OK;
}

grpc::Status DianaImpl::search(grpc::ServerContext*             context,
                               const SearchRequestMessage*      mes,
                               grpc::ServerWriter<SearchReply>* writer)
{
    if (async_search_) {
        return async_search(context, mes, writer);
    }
    return sync_search(context, mes, writer);
}

grpc::Status DianaImpl::sync_search(__attribute__((unused))
                                    grpc::ServerContext*             context,
                                    const SearchRequestMessage*      mes,
                                    grpc::ServerWriter<SearchReply>* writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start searching keyword ...");

    SearchRequest req = message_to_request(token_wrapper_, mes);

    std::vector<uint64_t> res_list(req.add_count);

    logger::logger()->trace("{} expected matches", req.add_count);

    if (req.add_count == 0) {
        logger::logger()->info("Empty request (no expected match)");
    } else {
        {
            SearchBenchmark bench("Diana synchronous search");
            server_->search_parallel(req, 8, res_list);
            bench.set_count(res_list.size());
        }
        for (auto& i : res_list) {
            SearchReply reply;
            reply.set_result(static_cast<uint64_t>(i));

            writer->Write(reply);
        }
    }
    logger::logger()->trace("Done searching");


    return grpc::Status::OK;
}


grpc::Status DianaImpl::async_search(__attribute__((unused))
                                     grpc::ServerContext*             context,
                                     const SearchRequestMessage*      mes,
                                     grpc::ServerWriter<SearchReply>* writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Start searching keyword...");

    std::atomic_uint res_size(0);

    std::mutex writer_lock;

    auto post_callback = [&writer, &res_size, &writer_lock](index_type i) {
        SearchReply reply;
        reply.set_result(static_cast<uint64_t>(i));

        writer_lock.lock();
        writer->Write(reply);
        writer_lock.unlock();

        res_size++;
    };

    auto req = message_to_request(token_wrapper_, mes);

    {
        SearchBenchmark bench("Diana asynchronous search");


        if (mes->add_count() >= 2) { // run the search algorithm in parallel
                                     // only if there are more than 2 results

            server_->search_parallel(
                req, post_callback, std::thread::hardware_concurrency());

        } else {
            server_->search(req, post_callback);
        }
        bench.set_count(res_size);
    }

    logger::logger()->trace("Done searching");


    return grpc::Status::OK;
}


grpc::Status DianaImpl::insert(__attribute__((unused))
                               grpc::ServerContext*        context,
                               const UpdateRequestMessage* mes,
                               __attribute__((unused))
                               google::protobuf::Empty* e)
{
    std::unique_lock<std::mutex> lock(update_mtx_);

    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Updating ...");

    server_->insert(message_to_request(mes));

    logger::logger()->trace("Update done");

    return grpc::Status::OK;
}

grpc::Status DianaImpl::bulk_insert(
    __attribute__((unused)) grpc::ServerContext*     context,
    grpc::ServerReader<UpdateRequestMessage>*        reader,
    __attribute__((unused)) google::protobuf::Empty* e)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server is not set up");
    }

    logger::logger()->trace("Updating (bulk)...");

    UpdateRequestMessage mes;

    while (reader->Read(&mes)) {
        server_->insert(message_to_request(&mes));
    }

    logger::logger()->trace("Updating (bulk)... done");


    flush_server_storage();

    return grpc::Status::OK;
}

bool DianaImpl::search_asynchronously() const
{
    return async_search_;
}

void DianaImpl::set_search_asynchronously(bool flag)
{
    async_search_ = flag;
}


void DianaImpl::flush_server_storage()
{
    if (server_) {
        logger::logger()->trace("Flush server storage...");

        server_->flush_edb();

        logger::logger()->trace("Flush server storage... done");
    }
}

SearchRequest message_to_request(
    const std::unique_ptr<crypto::Wrapper>& wrapper,
    const SearchRequestMessage*             mes)
{
    uint32_t add_count = mes->add_count();

    std::vector<uint8_t> rcprf_rep_buffer(mes->constrained_rcprf_rep().begin(),
                                          mes->constrained_rcprf_rep().end());
    constrained_rcprf_type rcprf
        = wrapper->unwrap<constrained_rcprf_type>(rcprf_rep_buffer);

    keyword_token_type kw_token;
    std::copy(mes->kw_token().begin(), mes->kw_token().end(), kw_token.begin());

    return SearchRequest(kw_token, std::move(rcprf), add_count);
}

UpdateRequest<DianaImpl::index_type> message_to_request(
    const UpdateRequestMessage* mes)
{
    UpdateRequest<DianaImpl::index_type> req;

    req.index = mes->index();
    std::copy(mes->update_token().begin(),
              mes->update_token().end(),
              req.token.begin());

    return req;
}

DianaServerRunner::DianaServerRunner(grpc::ServerBuilder& builder,
                                     const std::string&   server_db_path)
{
    service_.reset(new DianaImpl(server_db_path));

    builder.RegisterService(service_.get());
    server_ = builder.BuildAndStart();
}


DianaServerRunner::DianaServerRunner(const std::string& server_address,
                                     const std::string& server_db_path)
{
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    service_.reset(new DianaImpl(server_db_path));

    builder.RegisterService(service_.get());
    server_ = builder.BuildAndStart();
}

// as we forward-declare DianaImpl, we cannot use the default destructor
// NOLINTNEXTLINE(modernize-use-equals-default)
DianaServerRunner::~DianaServerRunner()
{
}

void DianaServerRunner::set_async_search(bool flag)
{
    service_->set_search_asynchronously(flag);
}

void DianaServerRunner::wait()
{
    server_->Wait();
}

void DianaServerRunner::shutdown()
{
    server_->Shutdown();
}

} // namespace diana
} // namespace sse
