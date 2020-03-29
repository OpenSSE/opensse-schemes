#pragma once

#include <sse/schemes/oceanus/types.hpp>

namespace sse {
namespace oceanus {


template<size_t PAGE_SIZE>
class OceanusServer
{
public:
    OceanusServer(const std::string& db_path);
    ~OceanusServer();

    std::list<index_type> search(const SearchRequest& req);

private:
};

OceanusServer::OceanusServer(const std::string& db_path)
{
}

OceanusServer::~OceanusServer()
{
}


std::list<index_type> OceanusServer::search(const SearchRequest& req);


} // namespace oceanus
} // namespace sse
