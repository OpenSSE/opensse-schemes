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
    SophosClientRunner(const std::string& address, const std::string& path, size_t setup_size = 1e5, size_t n_keywords = 1e4);
    
    void search(const std::string& keyword) const;
    void update(const std::string& keyword, uint64_t index);

private:
    bool send_setup(const size_t setup_size) const;
    
    std::unique_ptr<sophos::Sophos::Stub> stub_;
    std::unique_ptr<SophosClient> client_;
};

SearchRequestMessage request_to_message(const SearchRequest& req);
UpdateRequestMessage request_to_message(const UpdateRequest& req);

} // namespace sophos
} // namespace sse
