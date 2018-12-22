#include "utility.hpp"

#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <cstring>

#include <memory>
#include <string>

#include <gtest/gtest.h>

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


TEST(rocksdb, counters)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RocksDBCounter> db(
        new sophos::RocksDBCounter(rocksdb_test_dir));

    std::string key1 = "key1";
    std::string key2 = "key2";
    std::string key3 = "key3";

    std::string key_no_insert = "key_no_insert";

    uint32_t v1 = 1789;
    uint64_t v2 = 31416;

    uint32_t v_get = 0xFFFF;

    ASSERT_TRUE(db->set(key1, v1));
    ASSERT_TRUE(db->increment(key2, v2));
    ASSERT_TRUE(db->get_and_increment(key3, v_get));
    ASSERT_EQ(v_get, 0);

    // If we do this later, we will have an error
    EXPECT_EQ(db->approximate_size(), 3);

    std::string v_string;

    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);

    ASSERT_TRUE(db->get(key2, v_get));
    ASSERT_EQ(v2, v_get);

    ASSERT_TRUE(db->increment(key2, v2));
    ASSERT_TRUE(db->get(key2, v_get));
    ASSERT_EQ(v2 + 1, v_get);

    ASSERT_TRUE(db->get(key3, v_get));
    ASSERT_EQ(0, v_get);

    ASSERT_TRUE(db->get_and_increment(key3, v_get));
    ASSERT_EQ(1, v_get);

    ASSERT_TRUE(db->remove_key(key3));
    ASSERT_FALSE(db->get(key3, v_get));
}


TEST(rocksdb, counters_persistence)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RocksDBCounter> db(
        new sophos::RocksDBCounter(rocksdb_test_dir));

    std::string key1 = "key1";
    std::string key2 = "key2";
    std::string key3 = "key3";

    std::string key_no_insert = "key_no_insert";

    uint32_t v1 = 1789;
    uint32_t v2 = 31416;

    uint32_t v_get = 0xFFFF;

    ASSERT_TRUE(db->set(key1, v1));
    ASSERT_TRUE(db->increment(key2, v2));
    ASSERT_TRUE(db->get_and_increment(key3, v_get));
    ASSERT_EQ(v_get, 0);

    // probably useless, but increases the coverage
    db->flush(true);

    // close the database
    db.reset();

    // re-open the database
    db.reset(new sophos::RocksDBCounter(rocksdb_test_dir));

    ASSERT_TRUE(db->get(key1, v_get));
    ASSERT_EQ(v1, v_get);

    ASSERT_TRUE(db->get(key2, v_get));
    ASSERT_EQ(v2, v_get);

    ASSERT_TRUE(db->get(key3, v_get));
    ASSERT_EQ(0, v_get);
}

class TestSerializer
{
public:
    std::string serialize(const uint64_t c)
    {
        return std::string(reinterpret_cast<const char*>(&c),
                           reinterpret_cast<const char*>(&c)
                               + sizeof(uint64_t));
    }
    bool deserialize(std::string::iterator&       begin,
                     const std::string::iterator& end,
                     uint64_t&                    out)
    {
        if (end < begin + sizeof(uint64_t)) {
            EXPECT_EQ(end, begin);
            return false;
        }
        std::copy(
            begin, begin + sizeof(uint64_t), reinterpret_cast<uint8_t*>(&out));

        begin += sizeof(uint64_t);
        return true;
    }
};

TEST(rocksdb, lists)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RockDBListStore<uint64_t, TestSerializer>> db(
        new sophos::RockDBListStore<uint64_t, TestSerializer>(
            rocksdb_test_dir));

    std::array<uint8_t, 2> key1 = {{0, 1}};
    std::array<uint8_t, 3> key2 = {{0x42, 0x42, 0x00}};
    std::string            key3 = "primes";

    std::array<uint8_t, 4> key_no_insert = {{0xFF, 0XFF}};

    std::list<uint64_t> l1{{1, 2}};
    std::list<uint64_t> l2{{1789, 31416, 8080}};
    std::list<uint64_t> l3{{2, 3, 5, 7, 11, 13}};

    std::list<uint64_t> l_get;

    ASSERT_TRUE(db->put(key1, l1));
    ASSERT_TRUE(db->put(key2, l2));
    // ASSERT_TRUE(db->put(ke, l3));

    ASSERT_TRUE(db->get(key1, l_get));
    ASSERT_EQ(l1, l_get);

    ASSERT_TRUE(db->get(key2.data(), key2.size(), l_get));
    ASSERT_EQ(l2, l_get);

    ASSERT_TRUE(db->get(std::string(key2.begin(), key2.end()), l_get));
    ASSERT_EQ(l2, l_get);

    ASSERT_TRUE(db->put(key1, l2));
    ASSERT_TRUE(db->get(key1, l_get));
    ASSERT_EQ(l2, l_get);

    ASSERT_FALSE(db->get(key_no_insert, l_get));
}


TEST(rocksdb, lists_persistence)
{
    cleanup_directory(rocksdb_test_dir);

    std::unique_ptr<sophos::RockDBListStore<uint64_t, TestSerializer>> db(
        new sophos::RockDBListStore<uint64_t, TestSerializer>(
            rocksdb_test_dir));

    std::array<uint8_t, 2> key1 = {{0, 1}};
    std::array<uint8_t, 3> key2 = {{0x42, 0x42, 0x00}};

    std::list<uint64_t> l1{{1, 2}};
    std::list<uint64_t> l2{{1789, 31416, 8080}};
    std::list<uint64_t> l_get;

    ASSERT_TRUE(db->put(key1, l1));
    ASSERT_TRUE(db->put(key2, l2));

    ASSERT_TRUE(db->get(key1, l_get));
    ASSERT_EQ(l1, l_get);

    ASSERT_TRUE(db->get(key2, l_get));
    ASSERT_EQ(l2, l_get);

    ASSERT_TRUE(db->put(key1, l2));


    // probably useless, but increases the coverage
    db->flush(true);

    // close the database
    db.reset();

    // re-open the database
    db.reset(new sophos::RockDBListStore<uint64_t, TestSerializer>(
        rocksdb_test_dir));


    ASSERT_TRUE(db->get(key1, l_get));
    ASSERT_EQ(l2, l_get);
    ASSERT_TRUE(db->get(key2, l_get));
    ASSERT_EQ(l2, l_get);
}

} // namespace test
} // namespace sse
