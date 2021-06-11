#include <sse/schemes/tethys/details/tethys_graph.hpp>

#include <iostream>

#include <gtest/gtest.h>


namespace sse {
namespace tethys {

namespace details {
namespace test {

TEST(tethys_graph, dfs_1)
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
    auto   path = graph.find_source_sink_path(0, &cap);

    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    EXPECT_EQ(cap, 1);
    EXPECT_EQ(path_index, std::vector<size_t>({0, 1, 4, 5, 6}));
}

TEST(tethys_graph, dfs_2)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    graph.add_edge_from_source(0, 2, 0);
    graph.add_edge(1, 2, 0, 0 + mid_graph);

    graph.add_edge(4, 1, 0 + mid_graph, 2);
    graph.add_edge(5, 1, 2, 1 + mid_graph);
    graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    graph.add_edge(2, 1, 0 + mid_graph, 1);
    graph.add_edge_to_sink(3, 1, 1);

    size_t cap  = 0;
    auto   path = graph.find_source_sink_path(0, &cap);

    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    EXPECT_EQ(cap, 1);
    EXPECT_EQ(path_index, std::vector<size_t>({0, 1, 2, 3}));
}


TEST(tethys_graph, maxflow_1)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 2, 0);
    EdgePtr e_1 = graph.add_edge(1, 2, 0, 0 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 2);
    EXPECT_EQ(graph.get_edge_flow(e_1), 2);
    EXPECT_EQ(graph.get_edge_flow(e_2), 1);
    EXPECT_EQ(graph.get_edge_flow(e_3), 1);
    EXPECT_EQ(graph.get_edge_flow(e_4), 1);
    EXPECT_EQ(graph.get_edge_flow(e_5), 1);
    EXPECT_EQ(graph.get_edge_flow(e_6), 1);
}

TEST(tethys_graph, maxflow_2)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 1, 0);
    EdgePtr e_1 = graph.add_edge(1, 1, 0, 0 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);


    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 1);
    EXPECT_EQ(graph.get_edge_flow(e_1), 1);
    EXPECT_EQ(graph.get_edge_flow(e_2), 0);
    EXPECT_EQ(graph.get_edge_flow(e_3), 0);
    EXPECT_EQ(graph.get_edge_flow(e_4), 1);
    EXPECT_EQ(graph.get_edge_flow(e_5), 1);
    EXPECT_EQ(graph.get_edge_flow(e_6), 1);
}

TEST(tethys_graph, maxflow_3)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 1, 0);
    EdgePtr e_1 = graph.add_edge(1, 1, 0, 0 + mid_graph);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 1);
    EXPECT_EQ(graph.get_edge_flow(e_1), 1);
    EXPECT_EQ(graph.get_edge_flow(e_2), 1);
    EXPECT_EQ(graph.get_edge_flow(e_3), 1);
    EXPECT_EQ(graph.get_edge_flow(e_4), 0);
    EXPECT_EQ(graph.get_edge_flow(e_5), 0);
    EXPECT_EQ(graph.get_edge_flow(e_6), 0);
}


TEST(tethys_graph, maxflow_4)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 20, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 12, 8 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 12);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 12);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 0);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 12);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, maxflow_5)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 20, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 15);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 0);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 15);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, maxflow_6)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    EdgePtr sat_edge
        = graph.add_edge(3, 20, 1, 8 + mid_graph); // will saturate here


    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);


    // add these edges
    graph.add_edge(7, 9, 9, 3 + mid_graph);
    graph.add_edge(11, 9, 3 + mid_graph, 3);
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    graph.add_edge(14, 9, 6 + mid_graph, 1);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 20);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 5);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 20);

    EXPECT_EQ(graph.get_edge_flow(sat_edge), 20);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, maxflow_7)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph); // change this capacity

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 9, 9, 3 + mid_graph);
    graph.add_edge(11, 9, 3 + mid_graph, 3);
    EdgePtr sat_edge = graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 9, 6 + mid_graph, 1);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 22);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 7);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 22);

    EXPECT_EQ(graph.get_edge_flow(sat_edge), 7);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, maxflow_8)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph); // change this capacity

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    EdgePtr sat_edge_1
        = graph.add_edge(7, 9, 9, 3 + mid_graph); // saturate here
    EdgePtr sat_edge_2
        = graph.add_edge(11, 9, 3 + mid_graph, 3); // ... here ...
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    EdgePtr sat_edge_3 = graph.add_edge(14, 9, 6 + mid_graph, 1); // ..and here

    // add these edges
    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 9);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 9);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 9);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_3), 9);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, maxflow_9)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    EdgePtr sat_edge_1
        = graph.add_edge(7, 15, 9, 3 + mid_graph); // change this capacity
    EdgePtr sat_edge_2
        = graph.add_edge(11, 15, 3 + mid_graph, 3); // change this capacity
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    EdgePtr sat_edge_3
        = graph.add_edge(14, 15, 6 + mid_graph, 1); // change this capacity

    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 25);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 10);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 25);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 10);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 10);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_3), 10);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, maxflow_10)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1
        = graph.add_edge_from_source(0, 10, 1); // change this capacity
    EdgePtr e_source_2
        = graph.add_edge_from_source(1, 45, 9); // change this capacity

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 15, 9, 3 + mid_graph);
    graph.add_edge(11, 15, 3 + mid_graph, 3);
    EdgePtr sat_edge_1
        = graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 15, 6 + mid_graph, 1);

    EdgePtr sat_edge_2
        = graph.add_edge(4, 7, 3, 4 + mid_graph); // saturate here
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);


    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 10);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 14);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 7);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 7);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, maxflow_11)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1
        = graph.add_edge_from_source(0, 10, 1); // change this capacity
    EdgePtr e_source_2
        = graph.add_edge_from_source(1, 45, 9); // change this capacity

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 15, 9, 3 + mid_graph);
    graph.add_edge(11, 15, 3 + mid_graph, 3);
    graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 15, 6 + mid_graph, 1);

    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);


    // add these (useless) edges
    EdgePtr useless_edge_1 = graph.add_edge(10, 5, 2 + mid_graph, 7);
    EdgePtr useless_edge_2 = graph.add_edge(13, 2, 5 + mid_graph, 7);


    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 10);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 14);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(useless_edge_1), 0);
    EXPECT_EQ(graph.get_edge_flow(useless_edge_2), 0);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, parallel_maxflow_1)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 2, 0);
    EdgePtr e_1 = graph.add_edge(1, 2, 0, 0 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 2);
    EXPECT_EQ(graph.get_edge_flow(e_1), 2);
    EXPECT_EQ(graph.get_edge_flow(e_2), 1);
    EXPECT_EQ(graph.get_edge_flow(e_3), 1);
    EXPECT_EQ(graph.get_edge_flow(e_4), 1);
    EXPECT_EQ(graph.get_edge_flow(e_5), 1);
    EXPECT_EQ(graph.get_edge_flow(e_6), 1);
}

TEST(tethys_graph, parallel_maxflow_2)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 1, 0);
    EdgePtr e_1 = graph.add_edge(1, 1, 0, 0 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);


    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 1);
    EXPECT_EQ(graph.get_edge_flow(e_1), 1);
    EXPECT_EQ(graph.get_edge_flow(e_2), 0);
    EXPECT_EQ(graph.get_edge_flow(e_3), 0);
    EXPECT_EQ(graph.get_edge_flow(e_4), 1);
    EXPECT_EQ(graph.get_edge_flow(e_5), 1);
    EXPECT_EQ(graph.get_edge_flow(e_6), 1);
}

TEST(tethys_graph, parallel_maxflow_3)
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_0 = graph.add_edge_from_source(0, 1, 0);
    EdgePtr e_1 = graph.add_edge(1, 1, 0, 0 + mid_graph);

    EdgePtr e_4 = graph.add_edge(4, 1, 0 + mid_graph, 2);
    EdgePtr e_5 = graph.add_edge(5, 1, 2, 1 + mid_graph);
    EdgePtr e_6 = graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    EdgePtr e_2 = graph.add_edge(2, 1, 0 + mid_graph, 1);
    EdgePtr e_3 = graph.add_edge_to_sink(3, 1, 1);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();

    EXPECT_EQ(graph.get_edge_flow(e_0), 1);
    EXPECT_EQ(graph.get_edge_flow(e_1), 1);
    EXPECT_EQ(graph.get_edge_flow(e_2), 1);
    EXPECT_EQ(graph.get_edge_flow(e_3), 1);
    EXPECT_EQ(graph.get_edge_flow(e_4), 0);
    EXPECT_EQ(graph.get_edge_flow(e_5), 0);
    EXPECT_EQ(graph.get_edge_flow(e_6), 0);
}


TEST(tethys_graph, parallel_maxflow_4)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 20, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 12, 8 + mid_graph);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 12);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 12);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 0);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 12);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, parallel_maxflow_5)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 20, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 15);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 0);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 15);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, parallel_maxflow_6)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    EdgePtr sat_edge
        = graph.add_edge(3, 20, 1, 8 + mid_graph); // will saturate here


    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);


    // add these edges
    graph.add_edge(7, 9, 9, 3 + mid_graph);
    graph.add_edge(11, 9, 3 + mid_graph, 3);
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    graph.add_edge(14, 9, 6 + mid_graph, 1);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 20);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 5);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 20);

    EXPECT_EQ(graph.get_edge_flow(sat_edge), 20);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, parallel_maxflow_7)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph); // change this capacity

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 9, 9, 3 + mid_graph);
    graph.add_edge(11, 9, 3 + mid_graph, 3);
    EdgePtr sat_edge = graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 9, 6 + mid_graph, 1);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 22);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 7);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 22);

    EXPECT_EQ(graph.get_edge_flow(sat_edge), 7);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, parallel_maxflow_8)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph); // change this capacity

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    EdgePtr sat_edge_1
        = graph.add_edge(7, 9, 9, 3 + mid_graph); // saturate here
    EdgePtr sat_edge_2
        = graph.add_edge(11, 9, 3 + mid_graph, 3); // ... here ...
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    EdgePtr sat_edge_3 = graph.add_edge(14, 9, 6 + mid_graph, 1); // ..and here

    // add these edges
    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 9);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 9);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 9);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_3), 9);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, parallel_maxflow_9)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1 = graph.add_edge_from_source(0, 15, 1);
    EdgePtr e_source_2 = graph.add_edge_from_source(1, 10, 9);

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    EdgePtr sat_edge_1
        = graph.add_edge(7, 15, 9, 3 + mid_graph); // change this capacity
    EdgePtr sat_edge_2
        = graph.add_edge(11, 15, 3 + mid_graph, 3); // change this capacity
    graph.add_edge(5, 7, 3, 6 + mid_graph);
    EdgePtr sat_edge_3
        = graph.add_edge(14, 15, 6 + mid_graph, 1); // change this capacity

    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);

    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 25);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 15);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 10);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 25);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 10);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 10);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_3), 10);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

TEST(tethys_graph, parallel_maxflow_10)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1
        = graph.add_edge_from_source(0, 10, 1); // change this capacity
    EdgePtr e_source_2
        = graph.add_edge_from_source(1, 45, 9); // change this capacity

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 15, 9, 3 + mid_graph);
    graph.add_edge(11, 15, 3 + mid_graph, 3);
    EdgePtr sat_edge_1
        = graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 15, 6 + mid_graph, 1);

    EdgePtr sat_edge_2
        = graph.add_edge(4, 7, 3, 4 + mid_graph); // saturate here
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);


    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 10);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 14);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(sat_edge_1), 7);
    EXPECT_EQ(graph.get_edge_flow(sat_edge_2), 7);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}


TEST(tethys_graph, parallel_maxflow_11)
{
    const size_t graph_size = 20;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    EdgePtr e_source_1
        = graph.add_edge_from_source(0, 10, 1); // change this capacity
    EdgePtr e_source_2
        = graph.add_edge_from_source(1, 45, 9); // change this capacity

    graph.add_edge(3, 30, 1, 8 + mid_graph);

    EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7);
    EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8 + mid_graph);

    graph.add_edge(7, 15, 9, 3 + mid_graph);
    graph.add_edge(11, 15, 3 + mid_graph, 3);
    graph.add_edge(5, 7, 3, 6 + mid_graph); // saturate here
    graph.add_edge(14, 15, 6 + mid_graph, 1);

    graph.add_edge(4, 7, 3, 4 + mid_graph);
    graph.add_edge(12, 10, 4 + mid_graph, 6);
    graph.add_edge(6, 10, 6, 6 + mid_graph);


    // add these (useless) edges
    EdgePtr useless_edge_1 = graph.add_edge(10, 5, 2 + mid_graph, 7);
    EdgePtr useless_edge_2 = graph.add_edge(13, 2, 5 + mid_graph, 7);


    graph.parallel_compute_residual_maxflow();
    graph.transform_residual_to_flow();


    size_t flow = graph.get_flow();

    EXPECT_EQ(flow, 24);

    EXPECT_EQ(graph.get_edge_flow(e_source_1), 10);
    EXPECT_EQ(graph.get_edge_flow(e_source_2), 14);

    EXPECT_EQ(graph.get_edge_flow(e_sink_1), 0);
    EXPECT_EQ(graph.get_edge_flow(e_sink_2), 24);

    EXPECT_EQ(graph.get_edge_flow(useless_edge_1), 0);
    EXPECT_EQ(graph.get_edge_flow(useless_edge_2), 0);

    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr),
              graph.get_vertex_out_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_in_flow(kSinkPtr), flow);
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr),
              graph.get_vertex_in_flow(kSourcePtr));
    EXPECT_EQ(graph.get_vertex_out_flow(kSinkPtr), 0);
}

} // namespace test
} // namespace details
} // namespace tethys
} // namespace sse