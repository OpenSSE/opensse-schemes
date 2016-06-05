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

#include "sophos_core.hpp"

#include "sophos.grpc.pb.h"

#include <string>
#include <memory>
#include <mutex>

#include <grpc++/server.h>
#include <grpc++/server_context.h>

namespace sse {
namespace sophos {

    class SophosImpl final : public sophos::Sophos::Service {
    public:
        explicit SophosImpl(const std::string& path);
        
        grpc::Status setup(grpc::ServerContext* context,
                           const sophos::SetupMessage* request,
                           google::protobuf::Empty* e) override;
        
        grpc::Status search(grpc::ServerContext* context,
                            const sophos::SearchRequestMessage* request,
                            grpc::ServerWriter<sophos::SearchReply>* writer) override;
        
        grpc::Status sync_search(grpc::ServerContext* context,
                            const sophos::SearchRequestMessage* request,
                            grpc::ServerWriter<sophos::SearchReply>* writer);
        
        grpc::Status async_search(grpc::ServerContext* context,
                                  const sophos::SearchRequestMessage* request,
                                  grpc::ServerWriter<sophos::SearchReply>* writer);
        
        grpc::Status update(grpc::ServerContext* context,
                            const sophos::UpdateRequestMessage* request,
                            google::protobuf::Empty* e) override;
        
        grpc::Status bulk_update(grpc::ServerContext* context,
                                 grpc::ServerReader<sophos::UpdateRequestMessage>* reader,
                                 google::protobuf::Empty* e) override;
        
        std::ostream& print_stats(std::ostream& out) const;

        bool search_asynchronously() const;
        void set_search_asynchronously(bool flag);
        
        
    private:
        static const std::string pk_file;
        static const std::string pairs_map_file;

        std::unique_ptr<SophosServer> server_;
        std::string storage_path_;
        
        std::mutex update_mtx_;
        
        bool async_search_;
    };
    
    SearchRequest message_to_request(const SearchRequestMessage* mes);
    UpdateRequest message_to_request(const UpdateRequestMessage* mes);

    void run_sophos_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr, bool async_search);
} // namespace sophos
} // namespace sse
