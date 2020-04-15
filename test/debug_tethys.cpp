#include <sse/schemes/oceanus/details/tethys.hpp>

#include <sse/crypto/utils.hpp>

#include <fstream>
#include <iostream>
#include <memory>

using namespace sse::tethys;
using namespace sse::tethys::details;

void test_graphs()
{
    TethysGraph graph(3);

    graph.add_edge_from_source(0, 2, 0, 0);
    graph.add_edge(1, 2, 0, 0, ForcedRight);

    graph.add_edge(2, 1, 0, 1, ForcedLeft);
    graph.add_edge_to_sink(3, 1, 1, 0);

    graph.add_edge(4, 1, 0, 2, ForcedLeft);
    graph.add_edge(5, 1, 2, 1, ForcedRight);
    graph.add_edge_to_sink(6, 1, 1, 1);

    size_t cap  = 0;
    auto   path = graph.find_source_sink_path(&cap);

    for (const auto& e : path) {
        std::cerr << "Edge index: " << graph.get_edge(e).value_index << "\n";
    }

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();

    // std::cerr << graph << "\n";
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    test_graphs();
    sse::crypto::cleanup_crypto_lib();

    return 0;
}