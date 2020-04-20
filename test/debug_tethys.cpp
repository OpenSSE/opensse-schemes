#include <sse/schemes/tethys/details/tethys_graph.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>

#include <sse/crypto/utils.hpp>

#include <cassert>
#include <cstring>

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

constexpr size_t kTableKeySize = 16; // 128 bits table keys
using key_type                 = std::array<uint8_t, kTableKeySize>;

template<class Key, class T>
struct ValueEncoder
{
    static constexpr size_t kAdditionalKeyEntriesNumber
        = sizeof(Key) / sizeof(T) + (sizeof(Key) % sizeof(T) == 0 ? 0 : 1);

    static constexpr size_t kListLengthEntriesNumber
        = sizeof(TethysAssignmentInfo::list_length) / sizeof(T)
          + (sizeof(TethysAssignmentInfo::list_length) % sizeof(T) == 0 ? 0
                                                                        : 1);

    static constexpr size_t kControlBlockSizeEntries
        = 2 * (kAdditionalKeyEntriesNumber + kListLengthEntriesNumber);

    size_t encode(uint8_t*              buffer,
                  size_t                table_index,
                  const Key&            key,
                  const std::vector<T>& values,
                  TethysAssignmentInfo  infos)
    {
        (void)table_index;
        if (infos.assigned_list_length
            < kAdditionalKeyEntriesNumber + kListLengthEntriesNumber) {
            // return 0;
            std::fill(
                buffer, buffer + infos.assigned_list_length * sizeof(T), 0xDD);
            return infos.assigned_list_length * sizeof(T);
        }

        // we have to pay attention to the difference between the allocated list
        // size and the values' list size
        size_t encoded_list_size
            = infos.assigned_list_length
              - (kAdditionalKeyEntriesNumber
                 + kListLengthEntriesNumber); // we know this is positive
                                              // because of the previous test

        if (infos.dual_assigned_list_length
            < kAdditionalKeyEntriesNumber + kListLengthEntriesNumber) {
            // Some control blocks elements were spilled into our bucket
            // Do not consider them as real elements
            encoded_list_size -= kAdditionalKeyEntriesNumber
                                 + kListLengthEntriesNumber
                                 - infos.dual_assigned_list_length;
        }
        size_t encoded_list_offset = 0;

        if (infos.edge_orientation == IncomingEdge) {
            // Some of the first entries of the list might alread have been
            // encoded in an other bucket. infos.dual_assigned_list_length
            // (logical) elements have been allocated to the other bucket.

            // How many physical elements does that represent?
            if (infos.dual_assigned_list_length
                < kAdditionalKeyEntriesNumber + kListLengthEntriesNumber) {
                // no actual elements have been put in the other bucket
            } else {
                encoded_list_offset = infos.dual_assigned_list_length
                                      - (kAdditionalKeyEntriesNumber
                                         + kListLengthEntriesNumber);
            }
        }


        size_t offset = 0;

        // copy the key
        std::copy(reinterpret_cast<const uint8_t*>(&key),
                  reinterpret_cast<const uint8_t*>(&key) + sizeof(Key),
                  buffer + offset);
        offset += sizeof(Key); // offset = 16

        // fill with dummy bytes if needed
        std::fill(buffer + offset,
                  buffer + kAdditionalKeyEntriesNumber * sizeof(T),
                  0x11);
        offset = kAdditionalKeyEntriesNumber * sizeof(T); // offset = 16

        // append the length of the list
        std::copy(reinterpret_cast<const uint8_t*>(&encoded_list_size),
                  reinterpret_cast<const uint8_t*>(&encoded_list_size)
                      + sizeof(infos.assigned_list_length),
                  buffer + offset);
        offset += sizeof(infos.assigned_list_length); // offset = 24

        // fill with dummy bytes if needed
        std::fill(buffer + offset,
                  buffer + kControlBlockSizeEntries * sizeof(T),
                  0x22);
        offset = (kAdditionalKeyEntriesNumber + kListLengthEntriesNumber)
                 * sizeof(T); // offset = 24

        // now copy the values
        auto it_start = values.begin();


        it_start += encoded_list_offset;

        for (auto it = it_start; it != it_start + encoded_list_size; ++it) {
            T v = *it;
            std::copy(reinterpret_cast<const uint8_t*>(&v),
                      reinterpret_cast<const uint8_t*>(&v) + sizeof(T),
                      buffer + offset);
            offset += sizeof(T);
        }

        // for debugging, paint the remaining with an other patter
        std::fill(buffer + offset,
                  buffer + infos.assigned_list_length * sizeof(T),
                  0xDD);
        return infos.assigned_list_length * sizeof(T);
        // return offset;
    }

    void serialize_key_value(std::ostream&                           out,
                             const Key&                              k,
                             const TethysStashSerializationValue<T>& v)
    {
        out.write(reinterpret_cast<const char*>(k.data()), k.size());

        bool bucket_1_uf
            = (v.assignement_info.assigned_list_length
               < (kAdditionalKeyEntriesNumber + kListLengthEntriesNumber));

        bool bucket_2_uf
            = (v.assignement_info.dual_assigned_list_length
               < (kAdditionalKeyEntriesNumber + kListLengthEntriesNumber));


        size_t encoded_list_size_1 = 0;
        size_t encoded_list_size_2 = 0;

        if (!bucket_1_uf) {
            encoded_list_size_1
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesNumber + kListLengthEntriesNumber);

            if (bucket_2_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_1
                    -= kAdditionalKeyEntriesNumber + kListLengthEntriesNumber
                       - v.assignement_info.dual_assigned_list_length;
            }
        }
        if (!bucket_2_uf) {
            encoded_list_size_2
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesNumber
                     + kListLengthEntriesNumber); // we know this is positive
                                                  // because of the previous
                                                  // test

            if (bucket_1_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_2
                    -= kAdditionalKeyEntriesNumber + kListLengthEntriesNumber
                       - v.assignement_info.assigned_list_length;
            }
        }

        uint64_t v_size = v.assignement_info.list_length
                          - kControlBlockSizeEntries - encoded_list_size_1
                          - encoded_list_size_2;


        // write the size of the vector
        out.write(reinterpret_cast<const char*>(&v_size), sizeof(v_size));

        // and the elements
        for (auto it = v.data->end() - v_size; it != v.data->end(); ++it) {
            out.write(reinterpret_cast<const char*>(&(*it)), sizeof(*it));
        }
    }
};

struct Hasher
{
    TethysAllocatorKey operator()(const key_type& key)
    {
        TethysAllocatorKey tk;
        static_assert(sizeof(tk.h) == sizeof(key_type),
                      "Invalid source key size");

        memcpy(tk.h, key.data(), sizeof(tk.h));

        return tk;
    }
};

void test_store()
{
    const std::string test_dir = "test_dir";


    constexpr size_t kPageSize = 4096; // 4 kB

    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = 3;
    builder_params.tethys_table_path = test_dir + "/tethys_table.bin";
    builder_params.tethys_stash_path = test_dir + "/tethys_stash.bin";
    builder_params.epsilon           = 0.2;


    sse::utility::remove_directory(test_dir);
    sse::utility::create_directory(test_dir, static_cast<mode_t>(0700));


    TethysStoreBuilder<kPageSize,
                       key_type,
                       size_t,
                       ValueEncoder<key_type, size_t>,
                       Hasher>
        store_builder(builder_params);

    size_t              v_size = 450;
    key_type            key_0  = {{0x00}};
    std::vector<size_t> v_0(v_size, 0xABABABABABABABAB);
    for (size_t i = 0; i < v_0.size(); i++) {
        v_0[i] += i;
    }

    // force overflow
    key_type key_1 = key_0;
    key_1[8]       = 0x01;
    std::vector<size_t> v_1(v_size, 0xCDCDCDCDCDCDCDCD);
    for (size_t i = 0; i < v_1.size(); i++) {
        v_1[i] += i;
    }

    key_type key_2 = key_0;
    key_2[0]       = 0x01;
    key_2[8]       = 0x00;
    std::vector<size_t> v_2(v_size, 0xEFEFEFEFEFEFEFEF);
    for (size_t i = 0; i < v_2.size(); i++) {
        v_2[i] += i;
    }

    key_type key_3 = key_0;
    key_3[0]       = 0x01;
    key_3[8]       = 0x01;
    std::vector<size_t> v_3(v_size, 0x6969696969696969);
    for (size_t i = 0; i < v_3.size(); i++) {
        v_3[i] += i;
    }

    key_type key_4 = key_0;
    key_4[0]       = 0x01;
    key_4[8]       = 0x02;
    std::vector<size_t> v_4(v_size, 0x7070707070707070);
    for (size_t i = 0; i < v_4.size(); i++) {
        v_4[i] += i;
    }
    key_type key_5 = key_0;
    key_5[0]       = 0x02;
    key_5[8]       = 0x01;
    std::vector<size_t> v_5(v_size, 0x4242424242424242);
    for (size_t i = 0; i < v_5.size(); i++) {
        v_5[i] += i;
    }
    key_type key_6 = key_0;
    key_6[0]       = 0x02;
    key_6[8]       = 0x02;
    std::vector<size_t> v_6(v_size, 0x5353535353535353);
    for (size_t i = 0; i < v_6.size(); i++) {
        v_6[i] += i;
    }

    // key_type key_2 = key_0;
    // key_2[0]       = 0x01;
    // key_2[8]       = 0x00;


    // key_type key_3 = key_0;
    // key_3[0]       = 0x01;
    // key_3[8]       = 0x01;

    // key_type key_4 = key_0;
    // key_4[0]       = 0x01;
    // key_4[8]       = 0x01;

    // key_type key_5 = key_0;
    // key_5[0]       = 0x01;
    // key_5[8]       = 0x01;

    // key_type key_6 = key_0;
    // key_6[0]       = 0x01;
    // key_6[8]       = 0x01;


    store_builder.insert_list(key_0, v_0);
    store_builder.insert_list(key_1, v_1);
    store_builder.insert_list(key_2, v_2);
    store_builder.insert_list(key_3, v_3);
    store_builder.insert_list(key_4, v_4);
    store_builder.insert_list(key_5, v_5);
    store_builder.insert_list(key_6, v_6);

    store_builder.build();
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    // test_dfs();
    // test_graphs();
    test_store();
    sse::crypto::cleanup_crypto_lib();

    return 0;
}