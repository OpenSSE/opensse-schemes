#pragma once

#include <sse/schemes/tethys/details/tethys_graph.hpp>

#include <set>

namespace sse {
namespace tethys {
namespace details {

size_t tethys_graph_size(size_t n_elements, size_t bucket_size, double epsilon);

struct TethysAllocatorKey
{
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    uint64_t        h[2]{~0UL, ~0UL};
    EdgeOrientation orientation;

    TethysAllocatorKey() = default;
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
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


    const std::set<EdgePtr>& get_stashed_edges() const;
    const TethysGraph&       get_allocation_graph() const;
    bool                     has_allocated() const
    {
        return allocated;
    }

    void insert(TethysAllocatorKey key, size_t list_length, size_t index);

    void allocate();


    static constexpr size_t kEmptyIndexValue = ~0UL;

private:
    TethysGraph       allocation_graph;
    std::set<EdgePtr> stashed_edges;

    const size_t tethys_graph_size;
    const size_t page_size;
    bool         allocated{false};
};


} // namespace details
} // namespace tethys
} // namespace sse