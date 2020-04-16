#include "oceanus/details/tethys_graph.hpp"

#include <cassert>
#include <climits>

#include <deque>
#include <numeric>
#include <stdexcept>

namespace sse {
namespace tethys {

namespace details {

const Vertex& TethysGraph::get_vertex(VertexPtr ptr) const
{
    if (ptr == kSinkPtr) {
        return sink;
    }
    if (ptr == kSourcePtr) {
        return source;
    }

    return vertices[ptr];
}

Vertex& TethysGraph::get_vertex(VertexPtr ptr)
{
    if (ptr == kSinkPtr) {
        return sink;
    }
    if (ptr == kSourcePtr) {
        return source;
    }

    return vertices[ptr];
}

EdgePtr TethysGraph::add_edge(size_t          value_index,
                              ssize_t         cap,
                              size_t          start,
                              size_t          end,
                              EdgeOrientation orientation)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    if (start >= graph_size) {
        throw std::out_of_range("Start index out of bounds");
    }

    if (end >= graph_size) {
        throw std::out_of_range("End index out of bounds");
    }

    Edge e(value_index, cap);

    if (orientation == ForcedLeft) {
        e.start = VertexPtr(1, start);
        e.end   = VertexPtr(0, end);
    } else if (orientation == ForcedRight) {
        e.start = VertexPtr(0, start);
        e.end   = VertexPtr(1, end);
    } // here we will be able to add additional orientations such as 'least
      // charged'

    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    vertices[e.start].out_edges.push_back(e_ptr);
    vertices[e.end].in_edges.push_back(e_ptr);

    return e_ptr;
}

EdgePtr TethysGraph::add_edge_from_source(size_t  value_index,
                                          ssize_t cap,
                                          size_t  end,
                                          uint8_t table)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    if (end >= graph_size) {
        throw std::out_of_range("End index out of bounds");
    }

    if (table > 1) {
        throw std::out_of_range("Table should be 0 or 1");
    }

    Edge e(value_index, cap);

    e.start = kSourcePtr;

    if (table == 0) {
        e.end = VertexPtr(0, end);
    } else {
        e.end = VertexPtr(1, end);
    }
    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    source.out_edges.push_back(e_ptr);
    vertices[e.end].in_edges.push_back(e_ptr);

    return e_ptr;
}

EdgePtr TethysGraph::add_edge_to_sink(size_t  value_index,
                                      ssize_t cap,
                                      size_t  start,
                                      uint8_t table)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    if (start >= graph_size) {
        throw std::out_of_range("Start index out of bounds");
    }

    if (table > 1) {
        throw std::out_of_range("Table should be 0 or 1");
    }

    Edge e(value_index, cap);

    e.end = kSinkPtr;

    if (table == 0) {
        e.start = VertexPtr(0, start);
    } else {
        e.start = VertexPtr(1, start);
    }

    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    vertices[e.start].out_edges.push_back(e_ptr);
    sink.in_edges.push_back(e_ptr);

    return e_ptr;
}

void VertexVec::reset_parent_edges() const
{
    for (const Vertex& v : vertices[0]) {
        v.parent_edge = kNullEdgePtr;
    }

    for (const Vertex& v : vertices[1]) {
        v.parent_edge = kNullEdgePtr;
    }
}

void TethysGraph::reset_parent_edges() const
{
    sink.parent_edge   = kNullEdgePtr;
    source.parent_edge = kNullEdgePtr;


    vertices.reset_parent_edges();
}

std::vector<EdgePtr> TethysGraph::find_source_sink_path(size_t* path_flow) const
{
    reset_parent_edges();

    std::deque<VertexPtr> queue;
    queue.push_front(kSourcePtr);

    // bool first_vertex = true;
    bool found_sink = false; // flag for early exit
    // as we have two nested loops (and we do not want to use gotos), this flag
    // is necessary

    while (!found_sink) {
        if (queue.size() == 0) {
            break;
        }

        // get and pop the first element of the queue
        const Vertex& v = get_vertex(queue.front());
        queue.pop_front();

        // go through the outgoing edges of the selected vertex
        const std::vector<EdgePtr>& out_edges = v.out_edges;

        for (EdgePtr e_ptr : out_edges) {
            const Edge& e = edges[e_ptr];
            if (e.flow > 0) {
                const VertexPtr dest_ptr = e.end;
                const Vertex&   dest     = get_vertex(dest_ptr);

                if (dest.parent_edge == kNullEdgePtr
                    && dest_ptr != kSourcePtr) {
                    // TODO : add a flag to choose between DFS and BFS
                    // DFS for now
                    queue.push_front(dest_ptr);
                    dest.parent_edge = e_ptr;

                    if (dest_ptr == kSinkPtr) {
                        found_sink = true;
                        break;
                    }
                }
            }
        }

        // we also need to do the same thing for the reciprocal graph
        const std::vector<EdgePtr> in_edges = v.in_edges;
        for (EdgePtr e_ptr : in_edges) {
            const Edge& e = edges[e_ptr];
            if (e.rec_flow > 0) {
                const VertexPtr dest_ptr = e.start;
                const Vertex&   dest     = get_vertex(dest_ptr);

                if (dest.parent_edge == kNullEdgePtr
                    && dest_ptr != kSourcePtr) {
                    // TODO : add a flag to choose between DFS and BFS
                    // DFS for now
                    queue.push_front(dest_ptr);
                    // mark the parent edge as the reciprocal of the current
                    // edge
                    dest.parent_edge = e_ptr.reciprocal();

                    if (dest_ptr == kSinkPtr) {
                        found_sink = true;
                        break;
                    }
                }
            }
        }
    }

    // if (!found_sink) {
    //     std::cerr << "Did not found path from source to sink\n";
    // }

    if (sink.parent_edge != kNullEdgePtr) {
        // start by computing the size of the path
        ssize_t       flow = SSIZE_MAX;
        const Vertex* cur  = &sink;
        size_t        size = 0;

        while (cur->parent_edge != kNullEdgePtr) {
            const Edge& e = edges[cur->parent_edge];
            // be careful here: the flow we are interested in might be the
            // reciprocal flow
            flow = std::min<ssize_t>(edges.edge_flow(cur->parent_edge), flow);

            cur = &get_vertex(e.start);
            size++;
        }

        assert(size != 0);

        if (path_flow != nullptr) {
            *path_flow = flow;
        }

        std::vector<EdgePtr> path(size);


        cur      = &sink;
        size_t i = 0;
        while (cur->parent_edge != kNullEdgePtr) {
            path[size - i - 1] = cur->parent_edge;
            const Edge& e      = edges[cur->parent_edge];

            cur = &get_vertex(e.start);
            i++;
        }


        return path;
    }


    if (path_flow != nullptr) {
        *path_flow = 0;
    }
    return {};
}

void TethysGraph::compute_residual_maxflow()
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    while (true) {
        // find a path from source to sink
        size_t path_capacity;
        auto   path = find_source_sink_path(&path_capacity);

        if (path.size() == 0) {
            // no path found
            break;
        }

        for (EdgePtr e_ptr : path) {
            // update flows
            edges.update_flow(e_ptr, path_capacity);
        }
    }

    state = ResidualComputed;
}

void TethysGraph::transform_residual_to_flow()
{
    if (state != ResidualComputed) {
        throw std::invalid_argument(
            "Invalid inner state. State should be ResidualComputed.");
    }

    for (Edge& e : edges) {
        e.flow     = e.rec_flow;
        e.rec_flow = 0;
    }
    state = MaxFlowComputed;
}

size_t TethysGraph::get_flow() const
{
    if (state != MaxFlowComputed) {
        throw std::invalid_argument(
            "Invalid inner state. State should be MaxFlowComputed.");
    }

    size_t flow = 0;
    for (const EdgePtr e_ptr : source.out_edges) {
        flow += edges[e_ptr].flow;
    }

    return flow;
}

size_t TethysGraph::get_edge_capacity(EdgePtr e_ptr) const
{
    return edges[e_ptr].capacity;
}

size_t TethysGraph::get_edge_flow(EdgePtr e_ptr) const
{
    if (state != MaxFlowComputed) {
        throw std::invalid_argument(
            "Invalid inner state. State should be MaxFlowComputed.");
    }

    return edges[e_ptr].flow;
}


size_t TethysGraph::get_vertex_in_capacity(VertexPtr v_ptr) const
{
    const Vertex& v = get_vertex(v_ptr);

    return std::accumulate(
        v.in_edges.begin(),
        v.in_edges.end(),
        0UL,
        [&](size_t acc, EdgePtr e_ptr) { return acc + edges[e_ptr].capacity; });
}

size_t TethysGraph::get_vertex_out_capacity(VertexPtr v_ptr) const
{
    const Vertex& v = get_vertex(v_ptr);

    return std::accumulate(
        v.out_edges.begin(),
        v.out_edges.end(),
        0UL,
        [&](size_t acc, EdgePtr e_ptr) { return acc + edges[e_ptr].capacity; });
}

size_t TethysGraph::get_vertex_in_flow(VertexPtr v_ptr) const
{
    if (state != MaxFlowComputed) {
        throw std::invalid_argument(
            "Invalid inner state. State should be MaxFlowComputed.");
    }

    const Vertex& v = get_vertex(v_ptr);

    return std::accumulate(
        v.in_edges.begin(),
        v.in_edges.end(),
        0UL,
        [&](size_t acc, EdgePtr e_ptr) { return acc + edges[e_ptr].flow; });
}

size_t TethysGraph::get_vertex_out_flow(VertexPtr v_ptr) const
{
    if (state != MaxFlowComputed) {
        throw std::invalid_argument(
            "Invalid inner state. State should be MaxFlowComputed.");
    }

    const Vertex& v = get_vertex(v_ptr);

    return std::accumulate(
        v.out_edges.begin(),
        v.out_edges.end(),
        0UL,
        [&](size_t acc, EdgePtr e_ptr) { return acc + edges[e_ptr].flow; });
}
} // namespace details
} // namespace tethys
} // namespace sse
