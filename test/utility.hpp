#pragma once

#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace sse {
namespace test {
void cleanup_directory(const std::string& path);

template<class Client, class Server>
void insert_entry(const std::unique_ptr<Client>& client,
                  const std::unique_ptr<Server>& server,
                  const std::string&             keyword,
                  const uint64_t                 index)
{
    auto u_req = client->update_request(keyword, index);
    server->update(u_req);
}

template<class Client, class Server>
std::list<uint64_t> search_keyword(const std::unique_ptr<Client>& client,
                                   const std::unique_ptr<Server>& server,
                                   const std::string&             keyword)
{
    auto u_req = client->search_request(keyword);
    return server->search(u_req);
}

void iterate_database(
    const std::map<std::string, std::list<uint64_t>>&        db,
    const std::function<void(const std::string&, uint64_t)>& callback);

void iterate_database_keywords(
    const std::map<std::string, std::list<uint64_t>>& db,
    const std::function<void(const std::string&, const std::list<uint64_t>&)>&
        callback);

template<class Client, class Server>
void insert_database(const std::unique_ptr<Client>&                    client,
                     const std::unique_ptr<Server>&                    server,
                     const std::map<std::string, std::list<uint64_t>>& db)
{
    iterate_database(db,
                     [&client, &server](const std::string& kw, uint64_t index) {
                         sse::test::insert_entry(client, server, kw, index);
                     });
}


template<class Client, class Server>
void test_search_correctness(
    const std::unique_ptr<Client>&                    client,
    const std::unique_ptr<Server>&                    server,
    const std::map<std::string, std::list<uint64_t>>& db)

{
    auto test_callback = [&client,
                          &server](const std::string&         kw,
                                   const std::list<uint64_t>& expected_list) {
        const auto res_list = sse::test::search_keyword(client, server, kw);
        const std::set<uint64_t> res_set(res_list.begin(), res_list.end());
        const std::set<uint64_t> expected_set(expected_list.begin(),
                                              expected_list.end());

        ASSERT_EQ(res_set, expected_set);
    };
    iterate_database_keywords(db, test_callback);
}
} // namespace test
} // namespace sse