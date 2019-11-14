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


#pragma once

#include <sse/schemes/diana/diana_client.hpp>

#include <sse/crypto/wrapper.hpp>

#include <google/protobuf/empty.pb.h> // For ::google::protobuf::Empty

#include <grpcpp/grpcpp.h>
#include <grpcpp/support/sync_stream.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace sse {
namespace diana {


// Forward declaration of some GRPC types

// Because Stub is a nested class, we need to use a trick to forward-declare it
// See https://stackoverflow.com/a/50619244
#ifndef DIANA_CLIENT_RUNNER_CPP
namespace Diana {
class Stub;
} // namespace Diana
#endif

class SearchRequestMessage;
class UpdateRequestMessage;

class DianaClientRunner
{
public:
    using index_type = uint64_t;

    DianaClientRunner(const std::shared_ptr<grpc::Channel>& channel,
                      const std::string&                    path);

    DianaClientRunner(const DianaClientRunner&) = delete; // not copyable
    DianaClientRunner(DianaClientRunner&&)      = delete; // not movable

    ~DianaClientRunner();

    const DianaClient<index_type>& client() const;

    std::list<index_type> search(
        const std::string&                   keyword,
        const std::function<void(uint64_t)>& receive_callback = nullptr) const;
    void insert(const std::string& keyword, uint64_t index);

    void start_update_session();
    void end_update_session();
    void insert_in_session(const std::string& keyword, uint64_t index);
    void insert_in_session(
        const std::list<std::pair<std::string, uint64_t>>& update_list);

    bool load_inverted_index(const std::string& path);

    // not copyable by any mean
    DianaClientRunner& operator=(const DianaClientRunner& h) = delete;
    DianaClientRunner& operator=(DianaClientRunner& h) = delete;

private:
    void update_completion_loop();

    bool send_setup(const std::array<uint8_t, crypto::Wrapper::kKeySize>&
                        wrapping_key) const;

    std::unique_ptr<crypto::Wrapper> token_wrapper_;

    std::unique_ptr<diana::Diana::Stub>      stub_;
    std::unique_ptr<DianaClient<index_type>> client_;

    struct
    {
        std::unique_ptr<::grpc::ClientWriter<UpdateRequestMessage>> writer;
        std::unique_ptr<::grpc::ClientContext>                      context;
        ::google::protobuf::Empty                                   response;

        std::mutex mtx;
        bool       is_up{false};
    } bulk_update_state_;

    std::unique_ptr<grpc::ClientWriter<UpdateRequestMessage>>
        bulk_update_writer_;
};

SearchRequestMessage request_to_message(
    const std::unique_ptr<crypto::Wrapper>& wrapper,
    const SearchRequest&                    req);
UpdateRequestMessage request_to_message(
    const UpdateRequest<DianaClientRunner::index_type>& req);

} // namespace diana
} // namespace sse
