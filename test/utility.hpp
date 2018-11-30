#pragma once

#include <list>
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

} // namespace test
} // namespace sse