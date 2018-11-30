#include "utility.hpp"

#include <sse/schemes/utils/utils.hpp>

#include <gtest/gtest.h>

#include <string>

namespace sse {
namespace test {
void cleanup_directory(const std::string& path)
{
    utility::remove_directory(path);

    // create an empty directory
    bool success = utility::create_directory(path, 0700);
    ASSERT_TRUE(success);
}
} // namespace test
} // namespace sse