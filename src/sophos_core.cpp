//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

SophosServer::SophosServer(const std::string& db_path, const std::string& tdp_pk) :
edb_(db_path, 1000), public_tdp_(tdp_pk)
{
    
}