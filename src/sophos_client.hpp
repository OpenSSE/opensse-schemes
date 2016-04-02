//
//  sophos_client.hpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include "sophos_core.hpp"

#include "sophos.grpc.pb.h"

#include <memory>
#include <grpc++/channel.h>

namespace sse {
namespace sophos {

    class SophosClientRunner {
    public:
        SophosClientRunner(std::shared_ptr<grpc::Channel> channel, const std::string& path);
        
        void search(const std::string& keyword);
        void update(const std::string& keyword, uint64_t index);

    private:
        std::unique_ptr<sophos::Sophos::Stub> stub_;
    };
} // namespace sophos
} // namespace sse
