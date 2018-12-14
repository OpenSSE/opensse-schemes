#include <sse/runners/diana/client_runner.hpp>
#include <sse/runners/diana/server_runner.hpp>

namespace sse {
namespace diana {

namespace test {

#define SSE_DIANA_TEST_DIR "test_diana_runners"

class DianaRunner
{
public:
    using ClientRunner = sse::diana::DianaClientRunner;
    using ServerRunner = sse::diana::DianaServerRunner;

    static constexpr auto test_dir       = SSE_DIANA_TEST_DIR;
    static constexpr auto server_db_path = SSE_DIANA_TEST_DIR "/server.db";
    static constexpr auto client_db_path = SSE_DIANA_TEST_DIR "/client.db";
    static constexpr auto server_address = "127.0.0.1:4343";
};

} // namespace test
} // namespace diana
} // namespace sse
