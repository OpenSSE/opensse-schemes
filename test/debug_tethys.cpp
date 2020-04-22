#include <sse/schemes/tethys/details/tethys_graph.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>

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

template<class Key, class T, size_t PAGESIZE>
struct ValueEncoder
{
    static constexpr size_t kAdditionalKeyEntriesPerList
        = sizeof(Key) / sizeof(T) + (sizeof(Key) % sizeof(T) == 0 ? 0 : 1);

    static constexpr size_t kListLengthEntriesNumber
        = sizeof(TethysAssignmentInfo::list_length) / sizeof(T)
          + (sizeof(TethysAssignmentInfo::list_length) % sizeof(T) == 0 ? 0
                                                                        : 1);

    static constexpr size_t kListControlValues
        = 2 * (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);

    static constexpr size_t kBucketControlValues = 1;

    size_t start_block_encoding(uint8_t* buffer, size_t table_index)
    {
        (void)buffer;
        (void)table_index;
        return 0;
    }

    size_t encode(uint8_t*              buffer,
                  size_t                table_index,
                  const Key&            key,
                  const std::vector<T>& values,
                  TethysAssignmentInfo  infos)
    {
        (void)table_index;
        if (infos.assigned_list_length
            < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
            return 0;

            // for debugging only, not a valid encoding
            // std::fill(
            // buffer, buffer + infos.assigned_list_length * sizeof(T), 0xDD);
            // return infos.assigned_list_length * sizeof(T);
        }

        // we have to pay attention to the difference between the allocated list
        // size and the values' list size
        uint64_t encoded_list_size
            = infos.assigned_list_length
              - (kAdditionalKeyEntriesPerList
                 + kListLengthEntriesNumber); // we know this is positive
                                              // because of the previous test

        if (infos.dual_assigned_list_length
            < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
            // Some control blocks elements were spilled into our bucket
            // Do not consider them as real elements
            encoded_list_size -= kAdditionalKeyEntriesPerList
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
                < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
                // no actual elements have been put in the other bucket
            } else {
                encoded_list_offset = infos.dual_assigned_list_length
                                      - (kAdditionalKeyEntriesPerList
                                         + kListLengthEntriesNumber);
            }
        }


        size_t offset = 0;

        // copy the length of the list
        std::copy(reinterpret_cast<const uint8_t*>(&encoded_list_size),
                  reinterpret_cast<const uint8_t*>(&encoded_list_size)
                      + sizeof(encoded_list_size),
                  buffer + offset);
        offset += sizeof(encoded_list_size); // offset = 8

        // fill with dummy bytes if needed
        std::fill(buffer + offset,
                  buffer + kAdditionalKeyEntriesPerList * sizeof(T),
                  0x11);
        offset = kListLengthEntriesNumber * sizeof(T); // offset = 8

        // copy the key
        std::copy(reinterpret_cast<const uint8_t*>(&key),
                  reinterpret_cast<const uint8_t*>(&key) + sizeof(Key),
                  buffer + offset);
        offset += sizeof(Key); // offset = 24


        // fill with dummy bytes if needed
        std::fill(
            buffer + offset, buffer + kListControlValues * sizeof(T), 0x22);
        offset = (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber)
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

        // // for debugging, paint the remaining with an other patter
        // // this is a not a valid encoding
        // std::fill(buffer + offset,
        //           buffer + infos.assigned_list_length * sizeof(T),
        //           0xDD);
        // return infos.assigned_list_length * sizeof(T);
        return offset;
    }

    size_t finish_block_encoding(uint8_t* buffer,
                                 size_t   table_index,
                                 size_t   written_bytes,
                                 size_t   remaining_bytes)
    {
        (void)table_index;

        if (remaining_bytes == 0) {
            return 0;
        }

        memset(buffer + written_bytes, 0x00, remaining_bytes);
        return remaining_bytes;
    }

    void serialize_key_value(std::ostream&                           out,
                             const Key&                              k,
                             const TethysStashSerializationValue<T>& v)
    {
        out.write(reinterpret_cast<const char*>(k.data()), k.size());

        bool bucket_1_uf
            = (v.assignement_info.assigned_list_length
               < (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));

        bool bucket_2_uf
            = (v.assignement_info.dual_assigned_list_length
               < (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));


        size_t encoded_list_size_1 = 0;
        size_t encoded_list_size_2 = 0;

        if (!bucket_1_uf) {
            encoded_list_size_1
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);

            if (bucket_2_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_1
                    -= kAdditionalKeyEntriesPerList + kListLengthEntriesNumber
                       - v.assignement_info.dual_assigned_list_length;
            }
        }
        if (!bucket_2_uf) {
            encoded_list_size_2
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesPerList
                     + kListLengthEntriesNumber); // we know this is positive
                                                  // because of the previous
                                                  // test

            if (bucket_1_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_2
                    -= kAdditionalKeyEntriesPerList + kListLengthEntriesNumber
                       - v.assignement_info.assigned_list_length;
            }
        }

        uint64_t v_size = v.assignement_info.list_length - kListControlValues
                          - encoded_list_size_1 - encoded_list_size_2;


        // write the size of the vector
        out.write(reinterpret_cast<const char*>(&v_size), sizeof(v_size));

        // and the elements
        for (auto it = v.data->end() - v_size; it != v.data->end(); ++it) {
            out.write(reinterpret_cast<const char*>(&(*it)), sizeof(*it));
        }
    }

    std::pair<key_type, std::vector<T>> deserialize_key_value(std::istream& in)
    {
        key_type k;
        uint64_t v_size = 0;

        std::vector<T> v;

        in.read(reinterpret_cast<char*>(k.data()), k.size());

        // read the size of the vector
        in.read(reinterpret_cast<char*>(&v_size), sizeof(v_size));

        v.reserve(v_size);

        for (size_t i = 0; i < v_size; i++) {
            T elt;
            in.read(reinterpret_cast<char*>(&elt), sizeof(elt));
            v.push_back(elt);
        }

        return std::make_pair(k, v);
    }

    void decode_single_bucket(const Key&                           key,
                              const std::array<uint8_t, PAGESIZE>& bucket,
                              std::vector<T>& results) const
    {
        size_t offset = 0;

        Key      list_key;
        uint64_t list_length;

        while (offset < bucket.size()) {
            // read the length of the list
            memcpy(&list_length, bucket.data() + offset, sizeof(list_length));
            offset += sizeof(list_length);

            if (list_length == 0) {
                // we are at the end of the bucket
                break;
            }

            // read the key of the current list
            memcpy(&list_key, bucket.data() + offset, sizeof(list_key));
            offset += sizeof(list_key);

            if (list_key == key) {
                // match on the key
                results.reserve(results.size() + list_length);

                for (size_t i = 0; i < list_length; i++) {
                    T value;
                    memcpy(&value, bucket.data() + offset, sizeof(value));
                    offset += sizeof(value);

                    results.push_back(value);
                }

                break;
            } else {
                // jump to the next list
                offset += list_length * sizeof(T);
            }
        }
    }

    std::vector<T> decode_buckets(const Key&                           key,
                                  const std::array<uint8_t, PAGESIZE>& bucket_0,
                                  size_t,
                                  const std::array<uint8_t, PAGESIZE>& bucket_1,
                                  size_t)
    {
        std::vector<T> res;

        decode_single_bucket(key, bucket_0, res);
        decode_single_bucket(key, bucket_1, res);
        return res;
    }

    void start_tethys_encoding(const TethysGraph&)
    {
    }

    void finish_tethys_table_encoding()
    {
    }

    void finish_tethys_encoding()
    {
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

    {
        TethysStoreBuilder<kPageSize,
                           key_type,
                           size_t,
                           Hasher,
                           ValueEncoder<key_type, size_t, kPageSize>>
            store_builder(builder_params);

        store_builder.insert_list(key_0, v_0);
        store_builder.insert_list(key_1, v_1);
        store_builder.insert_list(key_2, v_2);
        store_builder.insert_list(key_3, v_3);
        store_builder.insert_list(key_4, v_4);
        store_builder.insert_list(key_5, v_5);
        store_builder.insert_list(key_6, v_6);

        store_builder.build();
    }
    {
        TethysStore<kPageSize,
                    key_type,
                    size_t,
                    Hasher,
                    ValueEncoder<key_type, size_t, kPageSize>>
            store(builder_params.tethys_table_path,
                  builder_params.tethys_stash_path);

        std::vector<size_t> res_0 = store.get_list(key_0);
        std::vector<size_t> res_1 = store.get_list(key_1);
        std::vector<size_t> res_2 = store.get_list(key_2);
        std::vector<size_t> res_3 = store.get_list(key_3);
        std::vector<size_t> res_4 = store.get_list(key_4);
        std::vector<size_t> res_5 = store.get_list(key_5);
        std::vector<size_t> res_6 = store.get_list(key_6);

        if (res_0 != v_0) {
            std::cerr << "Invalid list 0\n";
        }
        if (res_1 != v_1) {
            std::cerr << "Invalid list 1\n";
        }
        if (res_2 != v_2) {
            std::cerr << "Invalid list 2\n";
        }
        if (res_3 != v_3) {
            std::cerr << "Invalid list 3\n";
        }
        if (res_4 != v_4) {
            std::cerr << "Invalid list 4\n";
        }
        if (res_5 != v_5) {
            std::cerr << "Invalid list 5\n";
        }
        if (res_6 != v_6) {
            std::cerr << "Invalid list 6\n";
        }
    }
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