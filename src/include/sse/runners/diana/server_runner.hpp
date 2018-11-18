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

#include <sse/schemes/diana/diana_server.hpp>

#include <string>
#include <memory>
#include <mutex>

#include <grpc++/server.h>
#include <grpc++/server_context.h>

namespace sse {
    namespace diana {

        // Forward declaration of some GRPC types

        // Because Stub is a nested class, we need to use a trick to forward-declare it
        // See https://stackoverflow.com/a/50619244
        #ifndef DIANA_SERVER_RUNNER_CPP
        namespace Sophos{
            class Service;
        }
        #endif

        class SetupMessage;
        class SearchRequestMessage;
        class SearchReplyMessage;
        class UpdateRequestMessage; 

        #ifdef DIANA_SERVER_RUNNER_CPP 
        class DianaImpl final : public diana::Diana::Service {
        public:
            typedef uint64_t index_type;

            explicit DianaImpl(const std::string& path);
            ~DianaImpl();
            
            grpc::Status setup(grpc::ServerContext* context,
                               const SetupMessage* request,
                               google::protobuf::Empty* e) override;
            
            grpc::Status search(grpc::ServerContext* context,
                                const SearchRequestMessage* request,
                                grpc::ServerWriter<SearchReply>* writer) override;
            
            grpc::Status sync_search(grpc::ServerContext* context,
                                     const SearchRequestMessage* request,
                                     grpc::ServerWriter<SearchReply>* writer);
            
            grpc::Status async_search(grpc::ServerContext* context,
                                      const SearchRequestMessage* request,
                                      grpc::ServerWriter<SearchReply>* writer);
            
            grpc::Status update(grpc::ServerContext* context,
                                const UpdateRequestMessage* request,
                                google::protobuf::Empty* e) override;
            
            grpc::Status bulk_update(grpc::ServerContext* context,
                                     grpc::ServerReader<UpdateRequestMessage>* reader,
                                     google::protobuf::Empty* e) override;
            
            std::ostream& print_stats(std::ostream& out) const;
            
            bool search_asynchronously() const;
            void set_search_asynchronously(bool flag);
            
            void flush_server_storage();
            
        private:
            static const std::string pairs_map_file;
            
            std::unique_ptr<DianaServer<index_type>> server_;
            std::string storage_path_;
            
            std::mutex update_mtx_;
            
            bool async_search_;
        };
        
        SearchRequest message_to_request(const SearchRequestMessage* mes);
        UpdateRequest<DianaImpl::index_type> message_to_request(const UpdateRequestMessage* mes);
    
        #endif

        void run_diana_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr, bool async_search);
    }
}
