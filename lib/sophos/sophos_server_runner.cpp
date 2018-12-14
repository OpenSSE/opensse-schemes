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

#include <grpc++/security/server_credentials.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc/grpc.h>

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
            // error, the secret key file is not there
            throw std::runtime_error("Missing secret key file");
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
    logger::log(logger::LoggerSeverity::TRACE) << "Setup!" << std::endl;

    if (server_) {
        // problem, the server is already set up
        logger::log(logger::LoggerSeverity::ERROR)
            << "Info: server received a setup message but is already set up"
            << std::endl;

        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "The server was already set up");
    }

    // create the content directory but first check that nothing is already
    // there

    if (utility::exists(storage_path_)) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Error: Unable to create the server's content directory"
            << std::endl;

        return grpc::Status(grpc::ALREADY_EXISTS,
                            "Unable to create the server's content directory");
    }

    if (!utility::create_directory(storage_path_, static_cast<mode_t>(0700))) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Error: Unable to create the server's content directory"
            << std::endl;

        return grpc::Status(grpc::PERMISSION_DENIED,
                            "Unable to create the server's content directory");
    }

    // now, we have the directory, and we should be able to conclude the setup
    // however, the bucket_map constructor in SophosServer's constructor can
    // raise an exception, so we need to take care of it

    std::string pairs_map_path = storage_path_ + "/" + pairs_map_file;

    try {
        logger::log(logger::LoggerSeverity::INFO)
            << "Seting up server" << std::endl;
        server_.reset(new SophosServer(pairs_map_path, message->public_key()));
    } catch (std::exception& e) {
        logger::log(logger::LoggerSeverity::ERROR)
            << "Error when setting up the server's core" << std::endl;

        server_.reset();
        return grpc::Status(grpc::FAILED_PRECONDITION,
                            "Unable to create the server's core.");
    }

    // write the public key in a file
    std::string pk_path = storage_path_ + "/" + pk_file;

    std::ofstream pk_out(pk_path.c_str());
    if (!pk_out.is_open()) {
        // error

        logger::log(logger::LoggerSeverity::ERROR)
            << "Error when writing the public key" << std::endl;

        return grpc::Status(grpc::PERMISSION_DENIED,
                            "Unable to write the public key to disk");
    }
    pk_out << message->public_key();
    pk_out.close();

    logger::log(logger::LoggerSeverity::TRACE)
        << "Successful setup" << std::endl;

    return grpc::Status::OK;
}

#define PRINT_BENCH_SEARCH(t, c)                                               \
    ("SEARCH: "                                                                \
     + (((c) != 0) ? std::to_string((t) / (c)) + " ms/pair, "                  \
                         + std::to_string((c)) + " pairs"                      \
                   : std::to_string((t)) + " ms, no pair found"))

//#define PRINT_BENCH_SEARCH_PAR_RPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (with RPC), " + std::to_string((c)) + " pairs" : \
//std::to_string((t)) + " ms, no pair found" )
//
//#define PRINT_BENCH_SEARCH_PAR_NORPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (without RPC),
//" + std::to_string((c)) + " pairs" : \ std::to_string((t)) + " ms, no pair
// found" )
//

//#define PRINT_BENCH_SEARCH_PAR_RPC(t,c) \
//"Search (with PRC): " + std::to_string((c)) + " " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair" : \
//std::to_string((t)) + " ms, no pair found" )
//
//#define PRINT_BENCH_SEARCH_PAR_NORPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (without RPC),
//" + std::to_string((c)) + " pairs" : \ std::to_string((t)) + " ms, no pair
// found" )

#define PRINT_BENCH_SEARCH_PAR_RPC(t, c)                                       \
    std::to_string((c)) + " \t\t "                                             \
        + (((c) != 0) ? std::to_string((t) / (c)) : std::to_string((t)))

#define PRINT_BENCH_SEARCH_PAR_NORPC(t, c)                                     \
    std::to_string((c)) + " \t\t "                                             \
        + (((c) != 0) ? std::to_string((t) / (c)) : std::to_string((t)))


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

    logger::log(logger::LoggerSeverity::TRACE) << "Searching ...";
    std::list<uint64_t> res_list;

    auto req = message_to_request(mes);

    //    BENCHMARK_Q((res_list = server_->search(req)),res_list.size(),
    //    PRINT_BENCH_SEARCH_PAR_NORPC) BENCHMARK_Q((res_list =
    //    server_->search_parallel(req)),res_list.size(),
    //    PRINT_BENCH_SEARCH_PAR_NORPC) BENCHMARK_Q((res_list =
    //    server_->search_parallel_light(req,1)),res_list.size(),
    //    PRINT_BENCH_SEARCH_PAR_NORPC)
    BENCHMARK_Q((res_list = server_->search_parallel(req, 2)),
                res_list.size(),
                PRINT_BENCH_SEARCH_PAR_NORPC)
    //    BENCHMARK_Q((res_list =
    //    server_->search_parallel_light(req,3)),res_list.size(),
    //    PRINT_BENCH_SEARCH_PAR_NORPC) BENCHMARK_SIMPLE("\n\n",{;})

    for (auto& i : res_list) {
        sophos::SearchReply reply;
        reply.set_result(static_cast<uint64_t>(i));

        writer->Write(reply);
    }

    logger::log(logger::LoggerSeverity::TRACE) << " done" << std::endl;


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

    logger::log(logger::LoggerSeverity::TRACE) << "Searching ...";
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

    if (mes->add_count() >= 40) { // run the search algorithm in parallel only
                                  // if there are more than 2 results
        BENCHMARK_Q(
            (server_->search_parallel_callback(
                req, post_callback, std::thread::hardware_concurrency(), 8, 1)),
            res_size,
            PRINT_BENCH_SEARCH_PAR_RPC)
        //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes),
        //        post_callback, std::thread::hardware_concurrency())),res_size,
        //        PRINT_BENCH_SEARCH_PAR_RPC)
        //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes),
        //        post_callback, 10)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
    } else if (mes->add_count() >= 2) {
        BENCHMARK_Q(
            (server_->search_parallel_light_callback(
                req, post_callback, std::thread::hardware_concurrency())),
            res_size,
            PRINT_BENCH_SEARCH_PAR_RPC)
    } else {
        BENCHMARK_Q((server_->search_callback(req, post_callback)),
                    res_size,
                    PRINT_BENCH_SEARCH_PAR_RPC)
    }


    logger::log(logger::LoggerSeverity::TRACE) << " done" << std::endl;


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

    logger::log(logger::LoggerSeverity::TRACE) << "Updating ..." << std::endl;

    server_->insert(message_to_request(mes));

    logger::log(logger::LoggerSeverity::TRACE) << " done" << std::endl;

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

    logger::log(logger::LoggerSeverity::TRACE)
        << "Updating (bulk)..." << std::endl;

    sophos::UpdateRequestMessage mes;

    while (reader->Read(&mes)) {
        server_->insert(message_to_request(&mes));
    }

    logger::log(logger::LoggerSeverity::TRACE)
        << "Updating (bulk)... done" << std::endl;


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
