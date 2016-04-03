//
//  server_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_server.hpp"

#include <stdio.h>

int main(int argc, char** argv) {

    sse::sophos::run_sophos_server("0.0.0.0:4242", "test.ssdb");
    
    return 0;
}