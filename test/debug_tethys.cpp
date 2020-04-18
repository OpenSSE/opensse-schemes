#include <sse/schemes/tethys/details/tethys_graph.hpp>

#include <sse/crypto/utils.hpp>

#include <cassert>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>

using namespace sse::tethys;
using namespace sse::tethys::details;


void test_dfs()
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    graph.add_edge_from_source(0, 2, 0);
    graph.add_edge(1, 2, 0, 0 + mid_graph);

    graph.add_edge(2, 1, 0 + mid_graph, 1);
    graph.add_edge_to_sink(3, 1, 1);

    graph.add_edge(4, 1, 0 + mid_graph, 2);
    graph.add_edge(5, 1, 2, 1 + mid_graph);
    graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    size_t cap  = 0;
    auto   path = graph.find_source_sink_path(&cap);


    for (const auto& e : path) {
        std::cerr << "Edge index: " << graph.get_edge(e).value_index << "\n";
    }


    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    assert(cap == 1);
    assert(path_index == std::vector<size_t>({0, 1, 4, 5, 6}));
}

// void test_graphs()
// {
//     TethysGraph graph(10);

//     EdgePtr e_source_1 = graph.add_edge_from_source(0, 10, 1, 0);
//     EdgePtr e_source_2 = graph.add_edge_from_source(1, 40, 9, 0);

//     graph.add_edge(3, 30, 1, 8, ForcedRight);

//     EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8, 1);
//     EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7, 0);

//     graph.add_edge(7, 15, 9, 3, ForcedRight);
//     graph.add_edge(11, 15, 3, 3, ForcedLeft);
//     graph.add_edge(5, 7, 3, 6, ForcedRight);
//     graph.add_edge(14, 15, 6, 1, ForcedLeft);

//     graph.add_edge(4, 7, 3, 4, ForcedRight);
//     graph.add_edge(12, 10, 4, 6, ForcedLeft);
//     graph.add_edge(6, 10, 6, 6, ForcedRight);


//     // graph.add_edge(2, 6, 1, 4, ForcedRight);
//     // graph.add_edge(21, 6, 1, 2, ForcedRight);


//     // graph.add_edge(10, 5, 2, 7, ForcedLeft);


//     // graph.add_edge(13, 2, 5, 7, ForcedLeft);


//     graph.compute_residual_maxflow();
//     graph.transform_residual_to_flow();


//     size_t flow = graph.get_flow();

//     std::cerr << "Flow: " << flow << "\n";
//     std::cerr << "Source(1): " << graph.get_edge_flow(e_source_1) << "\n";
//     std::cerr << "Source(2): " << graph.get_edge_flow(e_source_2) << "\n";
//     std::cerr << "Sink(1): " << graph.get_edge_flow(e_sink_1) << "\n";
//     std::cerr << "Sink(2): " << graph.get_edge_flow(e_sink_2) << "\n";
// }

void test_graphs()
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    graph.add_edge_from_source(0, 1, 0);
    graph.add_edge(1, 1, 0, 0 + mid_graph);

    graph.add_edge(2, 1, 0 + mid_graph, 1);
    graph.add_edge_to_sink(3, 1, 1);

    graph.add_edge(4, 1, 0 + mid_graph, 2);
    graph.add_edge(5, 1, 2, 1 + mid_graph);
    graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    TethysGraph expected_graph(graph_size);

    expected_graph.add_edge_from_source(0, 1, 0);
    expected_graph.add_edge(1, 1, 0, 0 + mid_graph);

    expected_graph.add_edge(2, 1, 0 + mid_graph, 1);
    expected_graph.add_edge_to_sink(3, 1, 1);

    expected_graph.add_edge(4, 0, 0 + mid_graph, 2);
    expected_graph.add_edge(5, 0, 2, 1 + mid_graph);
    expected_graph.add_edge_to_sink(6, 0, 1 + mid_graph);
}
int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    // test_dfs();
    test_graphs();
    sse::crypto::cleanup_crypto_lib();

    return 0;
}