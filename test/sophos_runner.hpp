#include <sse/runners/sophos/sophos_client_runner.hpp>
#include <sse/runners/sophos/sophos_server_runner.hpp>
#include <sse/schemes/utils/utils.hpp>


namespace sse {
namespace sophos {
namespace test {

#define SSE_SOPHOS_TEST_DIR "test_sophos_runners"

class SophosRunner
{
public:
    using ClientRunner = sse::sophos::SophosClientRunner;
    using ServerRunner = sse::sophos::SophosServerRunner;

    static constexpr auto test_dir       = SSE_SOPHOS_TEST_DIR;
    static constexpr auto server_db_path = SSE_SOPHOS_TEST_DIR "/server.db";
    static constexpr auto client_db_path = SSE_SOPHOS_TEST_DIR "/client.db";
    static constexpr auto server_address = "127.0.0.1:4242";
};

} // namespace test
} // namespace sophos
} // namespace sse
