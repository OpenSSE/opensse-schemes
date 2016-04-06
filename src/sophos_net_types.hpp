//
//  sophos_net_types.hpp
//  sophos
//
//  Created by Raphael Bost on 06/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include <utility>
#include <memory>
#include <grpc/grpc.h>

namespace sse {
    namespace sophos {
        
        typedef struct
        {
            std::unique_ptr< google::protobuf::Empty > reply;
            std::unique_ptr< grpc::Status > status;
            std::unique_ptr< size_t > index;
        } update_tag_type;
        
    }
}