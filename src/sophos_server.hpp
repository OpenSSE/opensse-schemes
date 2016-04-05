//
//  sophos_server.hpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include "sophos_core.hpp"

#include "sophos.grpc.pb.h"

#include <string>
#include <memory>

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

        grpc::Status update(grpc::ServerContext* context,
                            const sophos::UpdateRequestMessage* request,
                            google::protobuf::Empty* e) override;
        
    private:
        static const std::string pk_file;
        static const std::string pairs_map_file;

        std::unique_ptr<SophosServer> server_;
        std::string storage_path_;
    };
    
    SearchRequest message_to_request(const SearchRequestMessage* mes);
    UpdateRequest message_to_request(const UpdateRequestMessage* mes);

    void run_sophos_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr);
} // namespace sophos
} // namespace sse
