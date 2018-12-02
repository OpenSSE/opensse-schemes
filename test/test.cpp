
#include "gtest/gtest.h"

#include <sse/schemes/utils/logger.hpp>

#include <sse/crypto/utils.hpp>

//  Google Test takes care of everything
//  Tests are automatically registered and run

int main(int argc, char* argv[])
{
    sse::crypto::init_crypto_lib();

    // Be sure to go through every branch of the logger, but still do not log
    // anything
    std::ostream null_stream(nullptr);
    sse::logger::set_logger_stream(&null_stream);
    sse::logger::set_severity(sse::logger::LoggerSeverity::DBG);

    ::testing::InitGoogleTest(&argc, argv);
    int rv = RUN_ALL_TESTS();

    sse::crypto::cleanup_crypto_lib();

    return rv;
}
