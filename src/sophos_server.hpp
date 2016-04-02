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

#include <grpc++/server_context.h>

namespace sse {
namespace sophos {

    class SophosImpl final : public sophos::Sophos::Service {
    public:
        explicit SophosImpl();
        
        grpc::Status setup(grpc::ServerContext* context,
                           const sophos::SetupMessage* request,
                           google::protobuf::Empty* e) override;
        
        grpc::Status search(grpc::ServerContext* context,
                            const sophos::SearchRequestMessage* request,
                            grpc::ServerWriter<sophos::SearchReply>* writer) override;

        grpc::Status update(grpc::ServerContext* context,
                            const sophos::UpdateRequestMessage* request,
                            google::protobuf::Empty* e) override;
    };
} // namespace sophos
} // namespace sse
