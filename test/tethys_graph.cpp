#include <sse/schemes/oceanus/details/tethys.hpp>

#include <iostream>

#include <gtest/gtest.h>


namespace sse {
namespace tethys {

namespace details {
namespace test {

TEST(tethys_graph, dfs_1)
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

    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    ASSERT_EQ(cap, 1);
    ASSERT_EQ(path_index, std::vector<size_t>({0, 1, 4, 5, 6}));
}

TEST(tethys_graph, dfs_2)
{
    TethysGraph graph(3);

    graph.add_edge_from_source(0, 2, 0, 0);
    graph.add_edge(1, 2, 0, 0, ForcedRight);

    graph.add_edge(4, 1, 0, 2, ForcedLeft);
    graph.add_edge(5, 1, 2, 1, ForcedRight);
    graph.add_edge_to_sink(6, 1, 1, 1);

    graph.add_edge(2, 1, 0, 1, ForcedLeft);
    graph.add_edge_to_sink(3, 1, 1, 0);


    size_t cap  = 0;
    auto   path = graph.find_source_sink_path(&cap);

    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    ASSERT_EQ(cap, 1);
    ASSERT_EQ(path_index, std::vector<size_t>({0, 1, 2, 3}));
}


TEST(tethys_graph, maxflow_1)
{
    TethysGraph graph(3);

    graph.add_edge_from_source(0, 2, 0, 0);
    graph.add_edge(1, 2, 0, 0, ForcedRight);

    graph.add_edge(2, 1, 0, 1, ForcedLeft);
    graph.add_edge_to_sink(3, 1, 1, 0);

    graph.add_edge(4, 1, 0, 2, ForcedLeft);
    graph.add_edge(5, 1, 2, 1, ForcedRight);
    graph.add_edge_to_sink(6, 1, 1, 1);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    TethysGraph expected_graph(3);

    expected_graph.add_edge_from_source(0, 2, 0, 0);
    expected_graph.add_edge(1, 2, 0, 0, ForcedRight);

    expected_graph.add_edge(2, 1, 0, 1, ForcedLeft);
    expected_graph.add_edge_to_sink(3, 1, 1, 0);

    expected_graph.add_edge(4, 1, 0, 2, ForcedLeft);
    expected_graph.add_edge(5, 1, 2, 1, ForcedRight);
    expected_graph.add_edge_to_sink(6, 1, 1, 1);

    ASSERT_EQ(graph, expected_graph);
}

TEST(tethys_graph, maxflow_2)
{
    TethysGraph graph(3);

    graph.add_edge_from_source(0, 1, 0, 0);
    graph.add_edge(1, 1, 0, 0, ForcedRight);

    graph.add_edge(2, 1, 0, 1, ForcedLeft);
    graph.add_edge_to_sink(3, 1, 1, 0);

    graph.add_edge(4, 1, 0, 2, ForcedLeft);
    graph.add_edge(5, 1, 2, 1, ForcedRight);
    graph.add_edge_to_sink(6, 1, 1, 1);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    TethysGraph expected_graph(3);

    expected_graph.add_edge_from_source(0, 1, 0, 0);
    expected_graph.add_edge(1, 1, 0, 0, ForcedRight);

    expected_graph.add_edge(2, 0, 0, 1, ForcedLeft);
    expected_graph.add_edge_to_sink(3, 0, 1, 0);

    expected_graph.add_edge(4, 1, 0, 2, ForcedLeft);
    expected_graph.add_edge(5, 1, 2, 1, ForcedRight);
    expected_graph.add_edge_to_sink(6, 1, 1, 1);

    ASSERT_EQ(graph, expected_graph);
}


TEST(tethys_graph, maxflow_3)
{
    TethysGraph graph(3);

    graph.add_edge_from_source(0, 1, 0, 0);
    graph.add_edge(1, 1, 0, 0, ForcedRight);

    graph.add_edge(4, 1, 0, 2, ForcedLeft);
    graph.add_edge(5, 1, 2, 1, ForcedRight);
    graph.add_edge_to_sink(6, 1, 1, 1);

    graph.add_edge(2, 1, 0, 1, ForcedLeft);
    graph.add_edge_to_sink(3, 1, 1, 0);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    TethysGraph expected_graph(3);

    expected_graph.add_edge_from_source(0, 1, 0, 0);
    expected_graph.add_edge(1, 1, 0, 0, ForcedRight);


    expected_graph.add_edge(4, 0, 0, 2, ForcedLeft);
    expected_graph.add_edge(5, 0, 2, 1, ForcedRight);
    expected_graph.add_edge_to_sink(6, 0, 1, 1);

    expected_graph.add_edge(2, 1, 0, 1, ForcedLeft);
    expected_graph.add_edge_to_sink(3, 1, 1, 0);

    ASSERT_EQ(graph, expected_graph);
}


} // namespace test
} // namespace details
} // namespace tethys
} // namespace sse