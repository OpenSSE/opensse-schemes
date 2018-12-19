#include "utility.hpp"

#include <sse/schemes/utils/utils.hpp>

#include <string>

#include <gtest/gtest.h>

namespace sse {
namespace test {
void cleanup_directory(const std::string& path)
{
    utility::remove_directory(path);

    // create an empty directory
    bool success = utility::create_directory(path, 0700);
    ASSERT_TRUE(success);
}

void iterate_database(
    const std::map<std::string, std::list<uint64_t>>&        db,
    const std::function<void(const std::string&, uint64_t)>& callback)
{
    for (auto it = db.begin(); it != db.end(); ++it) {
        const std::string& kw   = it->first;
        const auto&        list = it->second;
        for (auto index : list) {
            callback(kw, index);
        }
    }
}

void iterate_database_keywords(
    const std::map<std::string, std::list<uint64_t>>& db,
    const std::function<void(const std::string&, const std::list<uint64_t>&)>&
        callback)
{
    for (auto it = db.begin(); it != db.end(); ++it) {
        callback(it->first, it->second);
    }
}

} // namespace test
} // namespace sse