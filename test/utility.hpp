#pragma once

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>

#include <gtest/gtest.h>

namespace sse {
namespace test {
void cleanup_directory(const std::string& path);

template<class Client, class Server>
void insert_entry(const std::unique_ptr<Client>& client,
                  const std::unique_ptr<Server>& server,
                  const std::string&             keyword,
                  const uint64_t                 index)
{
    auto u_req = client->insertion_request(keyword, index);
    server->insert(u_req);
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

template<class ClientRunner>
void insert_database(const std::unique_ptr<ClientRunner>&              client,
                     const std::map<std::string, std::list<uint64_t>>& db)
{
    iterate_database(db, [&client](const std::string& kw, uint64_t index) {
        client->insert(kw, index);
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

        EXPECT_EQ(res_set, expected_set);
    };
    iterate_database_keywords(db, test_callback);
}

template<class Client, class Server, class SearchReqFun, class SearchFun>
void test_search_correctness(
    const std::unique_ptr<Client>&                    client,
    const std::unique_ptr<Server>&                    server,
    const std::map<std::string, std::list<uint64_t>>& db,
    SearchReqFun                                      search_req_fun,
    SearchFun                                         search_fun)

{
    auto test_callback = [&client, &server, &search_req_fun, &search_fun](
                             const std::string&         kw,
                             const std::list<uint64_t>& expected_list) {
        auto                     req      = search_req_fun(*client, kw);
        const auto               res_list = search_fun(*server, req);
        const std::set<uint64_t> res_set(res_list.begin(), res_list.end());
        const std::set<uint64_t> expected_set(expected_list.begin(),
                                              expected_list.end());

        EXPECT_EQ(res_set, expected_set);
    };
    iterate_database_keywords(db, test_callback);
}


template<class ClientRunner>
void test_search_correctness(
    const std::unique_ptr<ClientRunner>&              client,
    const std::map<std::string, std::list<uint64_t>>& db)

{
    auto test_callback = [&client](const std::string&         kw,
                                   const std::list<uint64_t>& expected_list) {
        const auto               res_list = client->search(kw);
        const std::set<uint64_t> res_set(res_list.begin(), res_list.end());
        const std::set<uint64_t> expected_set(expected_list.begin(),
                                              expected_list.end());

        EXPECT_EQ(res_set, expected_set);
    };
    iterate_database_keywords(db, test_callback);
}

} // namespace test
} // namespace sse