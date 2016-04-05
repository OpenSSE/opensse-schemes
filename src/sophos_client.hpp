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
#include <thread>
#include <atomic>
#include <grpc++/channel.h>

#include <mutex>
#include <condition_variable>

namespace sse {
namespace sophos {

class SophosClientRunner {
public:
    SophosClientRunner(const std::string& address, const std::string& path, size_t setup_size = 1e5, size_t n_keywords = 1e4);
    ~SophosClientRunner();
    
    const SophosClient& client() const;
    
    void search(const std::string& keyword) const;
    void update(const std::string& keyword, uint64_t index);
    void async_update(const std::string& keyword, uint64_t index);

    void wait_updates_completion();
private:
    void update_completion_loop();
    
    bool send_setup(const size_t setup_size) const;
    
    std::unique_ptr<sophos::Sophos::Stub> stub_;
    std::unique_ptr<SophosClient> client_;
    
    grpc::CompletionQueue update_cq_;

    std::atomic_size_t update_launched_count_, update_completed_count_;
    std::thread* update_completion_thread_;
    std::mutex update_completion_mtx_;
    std::condition_variable update_completion_cv_;

    std::mutex update_mtx_;
};

SearchRequestMessage request_to_message(const SearchRequest& req);
UpdateRequestMessage request_to_message(const UpdateRequest& req);

} // namespace sophos
} // namespace sse
