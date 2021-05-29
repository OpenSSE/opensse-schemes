#pragma once

#include <sse/schemes/utils/concat_iterator.hpp>
#include <sse/schemes/utils/thread_pool.hpp>

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

#include <stdexcept>
#include <vector>

namespace sse {
namespace tethys {
namespace details {

struct VertexPtr
{
    size_t index;

    // static constexpr size_t index_mask = ~0UL >> 1;
    constexpr VertexPtr() : index(~0UL){}; // null pointer by default

    constexpr explicit VertexPtr(size_t i) : index(i)
    {
    }

    bool operator==(const VertexPtr& ptr) const
    {
        return index == ptr.index;
    }

    bool operator!=(const VertexPtr& ptr) const
    {
        return index != ptr.index;
    }
};

static_assert(sizeof(VertexPtr) == sizeof(size_t), "Invalid VertexPtr size");


constexpr VertexPtr kNullVertexPtr = VertexPtr();
constexpr VertexPtr kSinkPtr       = VertexPtr(~0UL - 1);
constexpr VertexPtr kSourcePtr     = VertexPtr(~0UL - 2);


template<uint8_t size>
struct EdgePtr_Templ
{
    bool   is_reciprocal : 1;
    size_t index : size - 1;

    static constexpr size_t index_mask = ~0UL >> 1;

    constexpr EdgePtr_Templ()
        : is_reciprocal(false), index(~0UL & index_mask){};
    constexpr explicit EdgePtr_Templ(size_t i)
        : is_reciprocal(false), index(i & index_mask){};
    constexpr EdgePtr_Templ(bool r, size_t i)
        : is_reciprocal((static_cast<int>(r) & 1) != 0),
          index(i & index_mask){};


    bool operator==(const EdgePtr_Templ<size>& ptr) const
    {
        return *reinterpret_cast<const size_t*>(this)
               == *reinterpret_cast<const size_t*>(&ptr);
    }
    bool operator!=(const EdgePtr_Templ<size>& ptr) const
    {
        return *reinterpret_cast<const size_t*>(this)
               != *reinterpret_cast<const size_t*>(&ptr);
    }

    // only needed for the std::set collection
    bool operator<(const EdgePtr_Templ<size>& ptr) const
    {
        return (index < ptr.index)
               || (index == ptr.index && is_reciprocal < ptr.is_reciprocal);
    }

    EdgePtr_Templ reciprocal() const
    {
        return EdgePtr_Templ(!is_reciprocal, index);
    }
};

using EdgePtr = EdgePtr_Templ<sizeof(size_t) * 8>;

static_assert(sizeof(EdgePtr) == sizeof(size_t), "Invalid EdgePtr size");

constexpr EdgePtr kNullEdgePtr = EdgePtr();

struct Edge;
struct Vertex;

struct Edge
{
    size_t       value_index{~0UL};
    const size_t capacity;
    size_t       flow{0UL};
    size_t       rec_flow{0UL};
    VertexPtr    start{kNullVertexPtr};
    VertexPtr    end{kNullVertexPtr};

    Edge() = delete;

    Edge(size_t vi, size_t cap) : value_index(vi), capacity(cap), flow(cap)
    {
    }

    bool operator==(const Edge& e) const
    {
        return (value_index == e.value_index) && (capacity == e.capacity)
               && (flow == e.flow) && (rec_flow == e.rec_flow)
               && (start == e.start) && (end == e.end);
    }
};

class EdgeVec
{
public:
    EdgePtr push_back(Edge e)
    {
        edges.push_back(e);
        return EdgePtr(edges.size() - 1);
    }

    Edge& operator[](EdgePtr ptr)
    {
        return edges[ptr.index];
    }

    const Edge& operator[](EdgePtr ptr) const
    {
        return edges[ptr.index];
    }

    size_t edge_flow(EdgePtr ptr) const
    {
        const Edge& e = (*this)[ptr];
        if (ptr.is_reciprocal) {
            return e.rec_flow;
        }
        return e.flow;
    }

    void update_flow(EdgePtr ptr, size_t c)
    {
        Edge& e = (*this)[ptr];

        if (ptr.is_reciprocal) {
            e.flow += c;
            e.rec_flow -= c;
        } else {
            e.flow -= c;
            e.rec_flow += c;
        }
    }

    std::vector<Edge>::iterator begin()
    {
        return edges.begin();
    }
    std::vector<Edge>::iterator end()
    {
        return edges.end();
    }

    std::vector<Edge>::const_iterator begin() const
    {
        return edges.begin();
    }
    std::vector<Edge>::const_iterator end() const
    {
        return edges.end();
    }

    bool operator==(const EdgeVec& ev) const
    {
        return edges == ev.edges;
    }

private:
    std::vector<Edge> edges;
};

struct Vertex
{
    std::vector<EdgePtr> in_edges;
    std::vector<EdgePtr> out_edges;
    mutable EdgePtr      parent_edge;
    size_t               component{0};

    bool operator==(const Vertex& v) const
    {
        return (in_edges == v.in_edges) && (out_edges == v.out_edges);
    }
};

class VertexVec
{
public:
    using value_type      = Vertex;
    using size_type       = size_t;
    using difference_type = ptrdiff_t;
    using reference       = Vertex&;
    using const_reference = const Vertex&;
    using pointer         = Vertex*;
    using const_pointer   = const Vertex*;
    using iterator        = std::vector<Vertex>::iterator;
    using const_iterator  = std::vector<Vertex>::const_iterator;

    explicit VertexVec(size_t n) : vertices(n)
    {
    }

    size_t size() const
    {
        return vertices.size();
    }

    Vertex& operator[](VertexPtr ptr)
    {
        return vertices[ptr.index];
    }

    const Vertex& operator[](VertexPtr ptr) const
    {
        return vertices[ptr.index];
    }

    bool operator==(const VertexVec& vv) const
    {
        return (vertices == vv.vertices);
    }

    iterator begin()
    {
        return vertices.begin();
    }

    iterator end()
    {
        return vertices.end();
    }

    const_iterator begin() const
    {
        return vertices.begin();
    }

    const_iterator end() const
    {
        return vertices.end();
    }

private:
    friend class TethysGraph;

    void reset_parent_edges() const;

    std::vector<Vertex> vertices;
};

enum EdgeOrientation : uint8_t
{
    ForcedLeft  = 0,
    ForcedRight = 1
};

class TethysGraph
{
public:
    enum State : uint8_t
    {
        Building = 0,
        ResidualComputed,
        MaxFlowComputed
    };

    explicit TethysGraph(size_t n) : graph_size(n), vertices(n)
    {
        if (n == 0) {
            throw std::invalid_argument(
                "The size of the graph has to be non-zero");
        }
    }

    TethysGraph(const TethysGraph&) = delete;
    TethysGraph(TethysGraph&&)      = default;

    TethysGraph& operator=(const TethysGraph&) = delete;
    // TethysGraph& operator=(TethysGraph&&) = default;

    EdgePtr add_edge(size_t value_index, size_t cap, size_t start, size_t end);

    EdgePtr add_edge_from_source(size_t value_index, size_t cap, size_t end);
    EdgePtr add_edge_to_sink(size_t value_index, size_t cap, size_t start);

    std::vector<EdgePtr> find_source_sink_path(const size_t component,
                                               size_t*      path_flow) const;

    const Vertex& get_vertex(VertexPtr ptr) const;
    Vertex&       get_vertex(VertexPtr ptr);

    const Edge& get_edge(EdgePtr ptr) const
    {
        return edges[ptr];
    }
    Edge& get_edge(EdgePtr ptr)
    {
        return edges[ptr];
    }


    bool operator==(const TethysGraph& g) const
    {
        return (graph_size == g.graph_size) && (source == g.source)
               && (sink == g.sink) && (vertices == g.vertices)
               && (edges == g.edges);
    }

    void compute_connected_components();

    void compute_residual_maxflow();
    void parallel_compute_residual_maxflow(ThreadPool& thread_pool
                                           = ThreadPool::global_thread_pool());
    void transform_residual_to_flow();


    size_t get_flow() const;

    size_t get_edge_flow(EdgePtr e_ptr) const;
    size_t get_edge_capacity(EdgePtr e_ptr) const;

    size_t get_vertex_in_flow(VertexPtr v_ptr) const;
    size_t get_vertex_out_flow(VertexPtr v_ptr) const;

    size_t get_vertex_in_capacity(VertexPtr v_ptr) const;
    size_t get_vertex_out_capacity(VertexPtr v_ptr) const;

    const VertexVec& inner_vertices() const
    {
        return vertices;
    }

    VertexVec& inner_vertices()
    {
        return vertices;
    }

private:
    void reset_parent_edges() const;

    State state{Building};

    const size_t graph_size;

    Vertex    source;
    Vertex    sink;
    VertexVec vertices;
    EdgeVec   edges;

    size_t n_components{0};
};

} // namespace details
} // namespace tethys
} // namespace sse