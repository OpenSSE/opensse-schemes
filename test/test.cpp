
#include <sse/schemes/utils/logger.hpp>

#include <sse/crypto/utils.hpp>

#include <gtest/gtest.h>


namespace sse {
namespace test {
std::string JSON_test_library = "../inverted_index_test.json";
} // namespace test
} // namespace sse

//  Google Test takes care of everything
//  Tests are automatically registered and run

int main(int argc, char* argv[])
{
    sse::crypto::init_crypto_lib();

    // sse::logger::set_logger(std::shared_ptr<spdlog::logger>(nullptr));
    sse::logger::set_logging_level(spdlog::level::warn);

    ::testing::InitGoogleTest(&argc, argv);

    sse::Benchmark::set_benchmark_file("benchmark.log");

    // If there is one remaining argument, we use it as a pointer to the JSON
    // test library

    if (argc > 1) {
        sse::test::JSON_test_library = std::string(argv[1]);
        std::cerr << "JSON test library set to \""
                  << sse::test::JSON_test_library << "\"\n";
    }

    int rv = RUN_ALL_TESTS();

    sse::crypto::cleanup_crypto_lib();

    return rv;
}
