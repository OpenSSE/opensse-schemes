#pragma once

#include <cstdint>
#include <sys/types.h>

#include <vector>

namespace sse {
namespace tethys {

namespace details {

template<uint8_t size>
struct VertexPtr_Templ
{
    uint8_t table : 1;
    size_t  index : size - 1;

    static constexpr size_t index_mask = ~0UL >> 1;
    constexpr VertexPtr_Templ()
        : table(1), index(~0UL >> 1){}; // null pointer by default

    constexpr VertexPtr_Templ(uint8_t t, size_t i)
        : table(t & 1), index(i & index_mask)
    {
    }

    bool operator==(const VertexPtr_Templ<size>& ptr) const
    {
        return *reinterpret_cast<const size_t*>(this)
               == *reinterpret_cast<const size_t*>(&ptr);
    }

    bool operator!=(const VertexPtr_Templ<size>& ptr) const
    {
        return *reinterpret_cast<const size_t*>(this)
               != *reinterpret_cast<const size_t*>(&ptr);
    }
};

using VertexPtr = VertexPtr_Templ<sizeof(size_t) * 8>;

static_assert(sizeof(VertexPtr) == sizeof(size_t), "Invalid VertexPtr size");


constexpr VertexPtr kNullVertexPtr = VertexPtr();
constexpr VertexPtr kSinkPtr = VertexPtr_Templ<sizeof(size_t) * 8>(1, ~0UL - 1);
constexpr VertexPtr kSourcePtr
    = VertexPtr_Templ<sizeof(size_t) * 8>(1, ~0UL - 2);


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
        : is_reciprocal(r & 1), index(i & index_mask){};


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

    EdgePtr_Templ reciprocal()
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
        edges.push_back(std::move(e));
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
        } else {
            return e.flow;
        }
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

    bool operator==(const Vertex& v) const
    {
        return (in_edges == v.in_edges) && (out_edges == v.out_edges);
    }
};

class VertexVec
{
public:
    explicit VertexVec(size_t n)
    {
        vertices[0] = std::vector<Vertex>(n);
        vertices[1] = std::vector<Vertex>(n);
    }
    Vertex& operator[](VertexPtr ptr)
    {
        return vertices[ptr.table][ptr.index];
    }

    const Vertex& operator[](VertexPtr ptr) const
    {
        return vertices[ptr.table][ptr.index];
    }

    bool operator==(const VertexVec& vv) const
    {
        return (vertices[0] == vv.vertices[0])
               && (vertices[1] == vv.vertices[1]);
    }

private:
    friend class TethysGraph;

    void reset_parent_edges() const;

    std::vector<Vertex> vertices[2];
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
    }

    TethysGraph(const TethysGraph&) = delete;

    TethysGraph& operator=(const TethysGraph&) = delete;

    EdgePtr add_edge(size_t          value_index,
                     ssize_t         cap,
                     size_t          start,
                     size_t          end,
                     EdgeOrientation orientation);

    EdgePtr add_edge_from_source(size_t  value_index,
                                 ssize_t cap,
                                 size_t  end,
                                 uint8_t table);
    EdgePtr add_edge_to_sink(size_t  value_index,
                             ssize_t cap,
                             size_t  start,
                             uint8_t table);

    std::vector<EdgePtr> find_source_sink_path(size_t* path_capacity) const;

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

    void compute_residual_maxflow();
    void transform_residual_to_flow();


    size_t get_flow() const;

    size_t get_edge_flow(EdgePtr e_ptr) const;
    size_t get_edge_capacity(EdgePtr e_ptr) const;

    size_t get_vertex_in_flow(VertexPtr v_ptr) const;
    size_t get_vertex_out_flow(VertexPtr v_ptr) const;

    size_t get_vertex_in_capacity(VertexPtr v_ptr) const;
    size_t get_vertex_out_capacity(VertexPtr v_ptr) const;

private:
    void reset_parent_edges() const;

    State state{Building};

    const size_t graph_size;

    Vertex    source;
    Vertex    sink;
    VertexVec vertices;
    EdgeVec   edges;
};

} // namespace details
} // namespace tethys
} // namespace sse