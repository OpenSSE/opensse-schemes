#include "tethys/details/tethys_graph.hpp"

#include <sse/schemes/utils/logger.hpp>

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

EdgePtr TethysGraph::add_edge(size_t value_index,
                              size_t cap,
                              size_t start,
                              size_t end)
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

    e.start = VertexPtr(start);
    e.end   = VertexPtr(end);

    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    vertices[e.start].out_edges.push_back(e_ptr);
    vertices[e.end].in_edges.push_back(e_ptr);

    return e_ptr;
}

EdgePtr TethysGraph::add_edge_from_source(size_t value_index,
                                          size_t cap,
                                          size_t end)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    if (end >= graph_size) {
        throw std::out_of_range("End index out of bounds");
    }

    Edge e(value_index, cap);

    e.start = kSourcePtr;
    e.end   = VertexPtr(end);
    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    source.out_edges.push_back(e_ptr);
    vertices[e.end].in_edges.push_back(e_ptr);

    return e_ptr;
}

EdgePtr TethysGraph::add_edge_to_sink(size_t value_index,
                                      size_t cap,
                                      size_t start)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    if (start >= graph_size) {
        throw std::out_of_range("Start index out of bounds");
    }


    Edge e(value_index, cap);

    e.end   = kSinkPtr;
    e.start = VertexPtr(start);

    // add the edge and get the corresponding pointer
    EdgePtr e_ptr = edges.push_back(e);

    // add the pointer to the new edge to its ingoing and outgoing vertices
    vertices[e.start].out_edges.push_back(e_ptr);
    sink.in_edges.push_back(e_ptr);

    return e_ptr;
}

void VertexVec::reset_parent_edges() const
{
    for (const Vertex& v : *this) {
        v.parent_edge = kNullEdgePtr;
    }
}

void TethysGraph::reset_parent_edges() const
{
    sink.parent_edge   = kNullEdgePtr;
    source.parent_edge = kNullEdgePtr;


    vertices.reset_parent_edges();
}

std::vector<EdgePtr> TethysGraph::find_source_sink_path(const size_t component,
                                                        size_t* path_flow) const
{
    EdgePtr sink_parent_edge = kNullEdgePtr;

    std::vector<bool>     visited(vertices.size(), false);
    std::deque<VertexPtr> queue;
    queue.push_front(kSourcePtr);

    bool found_sink = false; // flag for early exit
    // as we have two nested loops (and we do not want to use gotos), this flag
    // is necessary

    while (!found_sink) {
        if (queue.empty()) {
            break;
        }

        // get and pop the first element of the queue
        const VertexPtr v_ptr = queue.front();
        const Vertex&   v     = get_vertex(v_ptr);
        queue.pop_front();

        // go through the outgoing edges of the selected vertex
        const std::vector<EdgePtr>& out_edges = v.out_edges;

        for (EdgePtr e_ptr : out_edges) {
            const Edge& e = edges[e_ptr];
            if (e.flow > 0) {
                const VertexPtr dest_ptr = e.end;
                const Vertex&   dest     = get_vertex(dest_ptr);

                if (dest_ptr == kSinkPtr) {
                    found_sink       = true;
                    sink_parent_edge = e_ptr;
                    //  dest.parent_edge = e_ptr;
                    break;
                }
                if (dest_ptr == kSourcePtr) {
                    // this was the first visited vertex, we can continue
                    continue;
                }
                if (!visited[dest_ptr.index] && dest_ptr != kSourcePtr) {
                    if (dest.component != component && v_ptr != kSourcePtr) {
                        std::cerr << "ERROR: vertex should be in the same "
                                     "component\n";
                    }
                    if (dest.component == component) {
                        // TODO : add a flag to choose between DFS and BFS
                        // DFS for now
                        queue.push_front(dest_ptr);
                        dest.parent_edge        = e_ptr;
                        visited[dest_ptr.index] = true;
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

                if (dest_ptr == kSinkPtr) {
                    found_sink = true;
                    // dest.parent_edge = e_ptr.reciprocal();
                    sink_parent_edge = e_ptr.reciprocal();

                    break;
                }
                if (dest_ptr == kSourcePtr) {
                    // this was the first visited vertex, we can continue
                    continue;
                }
                if (!visited[dest_ptr.index] && dest_ptr != kSourcePtr) {
                    if (dest.component != component && v_ptr != kSourcePtr) {
                        std::cerr << "ERROR: vertex should be in the same "
                                     "component\n";
                    }
                    if (dest.component == component) {
                        // TODO : add a flag to choose between DFS and BFS
                        // DFS for now
                        queue.push_front(dest_ptr);
                        // mark the parent edge as the reciprocal of the current
                        // edge
                        dest.parent_edge        = e_ptr.reciprocal();
                        visited[dest_ptr.index] = true;

                        // if (dest_ptr == kSinkPtr) {
                        //     found_sink = true;
                        //     break;
                        // }
                    }
                }
            }
        }
    }

    if (sink_parent_edge != kNullEdgePtr) {
        // start by computing the size of the path
        size_t        flow = SIZE_MAX;
        const Vertex* cur  = nullptr;
        size_t        size = 0;

        // treat the first vertex (the sink) a bit differently
        const Edge& e = edges[sink_parent_edge];
        // be careful here: the flow we are interested in might be the
        // reciprocal flow
        flow = std::min<size_t>(edges.edge_flow(sink_parent_edge), flow);

        if (sink_parent_edge.is_reciprocal) {
            // cppcheck-suppress redundantInitialization
            cur = &get_vertex(e.end);
        } else {
            cur = &get_vertex(e.start);
        }
        size++;

        while (cur->parent_edge != kNullEdgePtr) {
            const Edge& edge = edges[cur->parent_edge];
            // be careful here: the flow we are interested in might be the
            // reciprocal flow
            flow = std::min<size_t>(edges.edge_flow(cur->parent_edge), flow);

            if (cur->parent_edge.is_reciprocal) {
                cur = &get_vertex(edge.end);
            } else {
                cur = &get_vertex(edge.start);
            }
            size++;
        }

        assert(size != 0);

        if (path_flow != nullptr) {
            *path_flow = flow;
        }

        std::vector<EdgePtr> path(size);

        // again, treat the first vertex (the sink) a bit differently

        size_t i           = 0;
        path[size - i - 1] = sink_parent_edge;
        // const Edge& e      = edges[sink_parent_edge];

        if (sink_parent_edge.is_reciprocal) {
            // cppcheck-suppress redundantAssignment
            cur = &get_vertex(e.end);
        } else {
            cur = &get_vertex(e.start);
        }
        i++;

        while (cur->parent_edge != kNullEdgePtr) {
            path[size - i - 1] = cur->parent_edge;
            const Edge& edge   = edges[cur->parent_edge];

            if (cur->parent_edge.is_reciprocal) {
                cur = &get_vertex(edge.end);
            } else {
                cur = &get_vertex(edge.start);
            }
            i++;
        }


        return path;
    }


    if (path_flow != nullptr) {
        *path_flow = 0;
    }
    return {};
}

void TethysGraph::compute_connected_components()
{
    size_t component_index = 1;
    size_t max_size        = 1;
    for (size_t vi = 0; vi < vertices.size(); vi++) {
        VertexPtr vp(vi);
        if (vertices[vp].component != 0) {
            continue;
        }
        size_t component_size  = 0;
        vertices[vp].component = component_index;

        std::deque<VertexPtr> queue;

        queue.push_front(vp);

        while (!queue.empty()) {
            const Vertex& v = get_vertex(queue.front());
            queue.pop_front();
            component_size++;

            // go through the outgoing edges of the selected vertex
            const std::vector<EdgePtr>& out_edges = v.out_edges;

            for (EdgePtr e_ptr : out_edges) {
                const Edge&     e        = edges[e_ptr];
                const VertexPtr dest_ptr = e.end;

                if (dest_ptr == kSinkPtr || dest_ptr == kSourcePtr) {
                    continue;
                }

                Vertex& dest = get_vertex(dest_ptr);

                if (dest.component == 0) {
                    // TODO : add a flag to choose between DFS and BFS
                    // DFS for now
                    queue.push_front(dest_ptr);
                    dest.component = component_index;
                }
            }

            // we also need to do the same thing for the reciprocal graph
            const std::vector<EdgePtr> in_edges = v.in_edges;
            for (EdgePtr e_ptr : in_edges) {
                const Edge&     e        = edges[e_ptr];
                const VertexPtr dest_ptr = e.start;

                if (dest_ptr == kSinkPtr || dest_ptr == kSourcePtr) {
                    continue;
                }

                Vertex& dest = get_vertex(dest_ptr);
                if (dest.component == 0) {
                    // TODO : add a flag to choose between DFS and BFS
                    // DFS for now
                    queue.push_front(dest_ptr);
                    dest.component = component_index;
                }
            }
        }
        if (component_size == 1) {
            vertices[vp].component = 0;
        } else {
            // std::cout << component_size << "\n";
            max_size = std::max(max_size, component_size);
            component_index++;
        }
    }

    n_components = component_index - 1;
    std::cout << n_components << "\n";
    std::cout << max_size << "\n";
}

void TethysGraph::compute_residual_maxflow()
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    size_t computed_capacity = 0;
    size_t it                = 0;

    while (true) {
        // find a path from source to sink
        size_t path_capacity;
        auto   path = find_source_sink_path(0, &path_capacity);

        if (path.empty()) {
            // no path found
            break;
        }

        for (EdgePtr e_ptr : path) {
            // update flows
            edges.update_flow(e_ptr, path_capacity);
        }

        it++;
        computed_capacity += path_capacity;

        if ((it % 1000) == 0) {
            logger::logger()->info(
                "maxflow computation: {} iterations, computed capacity: {}",
                it,
                computed_capacity);
        }
    }

    logger::logger()->info(
        "maxflow computation completed: {} iterations, computed capacity: {}",
        it,
        computed_capacity);

    state = ResidualComputed;
}

void TethysGraph::parallel_compute_residual_maxflow(ThreadPool& thread_pool)
{
    if (state != Building) {
        throw std::invalid_argument(
            "Invalid inner state. State should be Building.");
    }

    compute_connected_components();

    std::vector<std::future<void>> jobs;

    std::cout << "Spawning " << n_components + 1 << " jobs\n";

    jobs.reserve(n_components + 1);

    std::atomic_size_t computed_capacity{0};
    std::atomic_size_t it{0};

    for (size_t component_index = 0; component_index <= n_components;
         component_index++) {
        auto job = [&, component_index]() {
            while (true) {
                // find a path from source to sink
                size_t path_capacity;
                auto   path
                    = find_source_sink_path(component_index, &path_capacity);

                if (path.empty()) {
                    // no path found
                    break;
                }

                for (EdgePtr e_ptr : path) {
                    // update flows
                    edges.update_flow(e_ptr, path_capacity);
                }
                it++;
                computed_capacity += path_capacity;

                if ((it % 1000) == 0) {
                    logger::logger()->info("parallel maxflow computation: {} "
                                           "iterations, computed capacity: {}",
                                           it,
                                           computed_capacity);
                }
            }
        };
        std::future<void> job_fut = thread_pool.enqueue(job);
        // job_fut.get();

        jobs.push_back(std::move(job_fut));
    }

    std::cout << "Wait for jobs completion\n";

    // wait for completion of the jobs
    for (auto& j : jobs) {
        j.get();
    }

    logger::logger()->info("parallel maxflow computation completed: {} "
                           "iterations, computed capacity: {}",
                           it,
                           computed_capacity);

    std::cout << "Maxflow jobs completed\n";

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
        // cppcheck-suppress useStlAlgorithm
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
