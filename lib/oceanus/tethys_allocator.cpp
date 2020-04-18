#include "oceanus/details/tethys_allocator.hpp"

#include <stdexcept>

namespace sse {
namespace tethys {
namespace details {

TethysAllocator::TethysAllocator(size_t table_size, size_t page_size)
    : allocation_graph(table_size), tethys_table_size(table_size),
      page_size(page_size)
{
}

void TethysAllocator::insert(TethysAllocatorKey key,
                             size_t             list_length,
                             size_t             index)
{
    if (index == ~0UL) {
        throw std::invalid_argument("Index must be different from -1");
    }

    if (list_length > page_size) {
        throw std::invalid_argument(
            "List length must be smaller than the page size");
    }

    allocation_graph.add_edge(index, list_length, key.h[0], key.h[1]);
}

void TethysAllocator::allocate()
{
    // We have to run the allocation algorithm which we recall here:
    // 1. For each vertex $i$, compute its outdegree $d$.
    // 	 a. If $d > p$, add $d-p$ edges from the source $s$ to $i$.
    // 	 b. If $d < p$, add $p-d$ edges from $i$ to the sink $t$.
    // 2. Compute a max flow from $s$ to $t$ using any max flow algorithm.
    // 3. Flip every edge that carries flow.
    // 4. Each element $e$ is assigned to the bin/vertex that is at the
    // origin of its associated edge (so the outdegree of a vertex should
    // be interpreted as the load of the bin), so if said bin has number $n_e$,
    // add $e$ to $B[n_e]$.
    // 5. For each bin $B[i]$, if its load is $x > p$,
    // then $x-p$ elements are removed from $B[i]$ and added to $S$.

    // At the end of the algorithm, the allocation will be encoded in the
    // following way: For each list represented as an edge e, e.flow elements
    // will go the start vertex, e.rec_flow elements to the end vertex, and
    // e.capacity - e.flow - e.rec_flow elements to the stash.


    // Step 1.: enumerate through the vertices

    for (size_t i = 0; i < tethys_table_size; i++) {
        VertexPtr v_ptr(i);

        size_t d = allocation_graph.get_vertex_out_capacity(v_ptr);

        if (d > page_size) {
            // Step 1.a.
            allocation_graph.add_edge_from_source(
                kEmptyIndexValue, d - page_size, i);
        } else if (d < page_size) {
            // Step 1.b.
            allocation_graph.add_edge_to_sink(
                kEmptyIndexValue, page_size - d, i);
        }
    }

    // Step 2.: Compute max flow on the graph
    allocation_graph.compute_residual_maxflow();
    // here, we should transform the residual maxflow graph, obtained from the
    // Ford-Fulkerson algorithm to the real maxflow graph using the following
    // line: allocation_graph.transform_residual_to_flow();

    // But remember: in step 3. we must flip every edge that carries flow. This
    // is actually what we already do in the transform_residual_to_flow()
    // method. As this operation is its own inverse, there is no point in doing
    // it twice; just don't do it.

    // Ok, we are almost done here. Remember that, because we only logically
    // flipped the edges carrying flow, the outdegree of a vertex is not only
    // the sum of the flow for the outgoing edges, but also the sum of the
    // reciproqual flow of incoming edges.
    // The last thing we have to do is to deal with overflowing bins.
}

} // namespace details
} // namespace tethys
} // namespace sse