//
//  db_generator.hpp
//  sophos
//
//  Created by Raphael Bost on 28/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#pragma once

#include "sophos_client_runner.hpp"

namespace sse {
    namespace sophos {
        void gen_db(SophosClientRunner& client, size_t N_entries);
    }
}