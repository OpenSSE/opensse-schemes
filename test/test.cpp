
#include "gtest/gtest.h"

#include <sse/crypto/utils.hpp>

//  Google Test takes care of everything
//  Tests are automatically registered and run

int main(int argc, char* argv[])
{
    sse::crypto::init_crypto_lib();

    ::testing::InitGoogleTest(&argc, argv);
    int rv = RUN_ALL_TESTS();

    sse::crypto::cleanup_crypto_lib();

    return rv;
}
