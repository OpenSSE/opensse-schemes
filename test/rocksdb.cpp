#include "utility.hpp"

#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <cstring>
#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace sse {
namespace test {

constexpr auto rocksdb_test_dir = "rocksdb_test";

TEST(rocksdb, entry_insertion)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RockDBWrapper> db(
        new sophos::RockDBWrapper(rocksdb_test_dir));

    std::array<uint8_t, 2> key1{{0x00, 0x01}};
    std::array<uint8_t, 3> key2{{0x00, 0x01, 0x02}};
    std::array<uint8_t, 4> key3{{0x42, 0x42, 0x00, 0x00}};
    std::array<uint8_t, 2> key_no_insert{{0xFF, 0xFF}};

    uint64_t v1 = 1789;
    uint64_t v2 = 31416;
    uint64_t v3 = 8080;


    ASSERT_TRUE(db->put(key1, v1));
    ASSERT_TRUE(db->put(key2, v2));
    ASSERT_TRUE(db->put(key3, v3));

    uint64_t    v_get = 0;
    std::string v_string;

    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);

    ASSERT_TRUE(db->get(std::string(key2.begin(), key2.end()), v_string));
    ASSERT_EQ(std::string(reinterpret_cast<char*>(&v2),
                          reinterpret_cast<char*>(&v2) + sizeof(v2)),
              v_string);

    ASSERT_TRUE(db->get(key3.data(), key3.size(), v_get));
    ASSERT_EQ(v3, v_get);

    ASSERT_FALSE(db->get(key_no_insert, v_get));

    EXPECT_EQ(db->approximate_size(), 3);
}

TEST(rocksdb, entry_removal)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RockDBWrapper> db(
        new sophos::RockDBWrapper(rocksdb_test_dir));

    std::array<uint8_t, 2> key1{{0x01, 0x00}};
    std::array<uint8_t, 2> key2{{0x02, 0x00}};

    uint64_t v1 = 1789;
    uint64_t v2 = 31416;


    ASSERT_TRUE(db->put(key1, v1));
    ASSERT_TRUE(db->put(key2, v2));

    uint64_t v_get = 0;

    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);

    ASSERT_TRUE(db->get(key2, v_get));
    ASSERT_EQ(v2, v_get);

    ASSERT_TRUE(db->remove(key1));
    ASSERT_FALSE(db->get(key1, v_get));

    ASSERT_TRUE(db->remove(key2.data(), key2.size()));
    ASSERT_FALSE(db->get(key2, v_get));
}


TEST(rocksdb, entry_persistence)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RockDBWrapper> db(
        new sophos::RockDBWrapper(rocksdb_test_dir));

    std::array<uint8_t, 2> key1{{0x01, 0x00}};

    uint64_t v1 = 1789;


    ASSERT_TRUE(db->put(key1, v1));

    uint64_t v_get = 0;

    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);

    // probably useless, but increases the coverage
    db->flush(true);

    // close the database
    db.reset();

    // re-open the database
    db.reset(new sophos::RockDBWrapper(rocksdb_test_dir));


    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);
}

} // namespace test
} // namespace sse
