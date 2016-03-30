//
//  sophos_core.hpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include <string>

#include <ssdmap/bucket_map.hpp>
#include <sse/crypto/tdp.hpp>

class SophosClient {
public:


private:
    
};

class SophosServer {
public:
    
    SophosServer(const std::string& db_path, const std::string& tdp_pk);
    
private:
    ssdmap::bucket_map<uint64_t, uint64_t> edb_;
    sse::crypto::Tdp public_tdp_;
};