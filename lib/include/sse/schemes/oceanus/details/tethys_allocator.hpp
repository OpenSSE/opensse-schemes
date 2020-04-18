#pragma once

#include <sse/schemes/oceanus/details/tethys_graph.hpp>

namespace sse {
namespace tethys {
namespace details {

struct TethysAllocatorKey
{
    uint64_t        h[2]{~0UL, ~0UL};
    EdgeOrientation orientation;

    TethysAllocatorKey() = default;
    TethysAllocatorKey(uint64_t v[2], EdgeOrientation o)
        : h{v[0], v[1]}, orientation(o)
    {
    }
    TethysAllocatorKey(size_t h0, size_t h1, EdgeOrientation o)
        : h{h0, h1}, orientation(o)
    {
    }
};

class TethysAllocator
{
public:
    TethysAllocator(size_t table_size, size_t page_size);

    void insert(TethysAllocatorKey key, size_t list_length, size_t index);

    void allocate();

    static constexpr size_t kEmptyIndexValue = ~0UL;

private:
    TethysGraph allocation_graph;

    const size_t tethys_table_size;
    const size_t page_size;
};


} // namespace details
} // namespace tethys
} // namespace sse