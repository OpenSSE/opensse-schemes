
#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/abstractio/kv_serializer.hpp>
#include <sse/schemes/tethys/core_types.hpp>
#include <sse/schemes/tethys/details/tethys_allocator.hpp>

#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace sse {
namespace tethys {

struct TethysStoreBuilderParam
{
    std::string tethys_table_path;
    std::string tethys_stash_path;

    size_t max_n_elements;
    double epsilon;

    size_t graph_size(size_t bucket_size) const
    {
        return details::tethys_graph_size(max_n_elements, bucket_size, epsilon);
    }
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueEncoder,
         class StashEncoder = ValueEncoder>
class TethysStoreBuilder
{
public:
    using key_type           = Key;
    using value_type         = T;
    using value_encoder_type = ValueEncoder;
    using stash_encoder_type = StashEncoder;


    static constexpr size_t kPayloadSize = PAGE_SIZE;
    using payload_type                   = std::array<uint8_t, kPayloadSize>;

    static constexpr size_t kBucketSize = PAGE_SIZE / sizeof(T);
    static constexpr size_t kMaxListSize
        = kBucketSize - value_encoder_type::kListControlValues;

    explicit TethysStoreBuilder(TethysStoreBuilderParam p);

    void insert_list(const Key& key, const std::vector<T>& val);

    void build();
    void build(ValueEncoder& encoder, StashEncoder& stash_encoder);

private:
    struct TethysData
    {
        using key_type   = Key;
        using value_type = std::vector<T>;

        const key_type   key;
        const value_type values;

        TethysData(key_type k, value_type v)
            : key(std::move(k)), values(std::move(v))
        {
        }
    };

    TethysStoreBuilderParam  params;
    details::TethysAllocator allocator;
    std::vector<TethysData>  data;

    bool is_built{false};
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueEncoder,
         class StashEncoder>
TethysStoreBuilder<PAGE_SIZE,
                   Key,
                   T,
                   TethysHasher,
                   ValueEncoder,
                   StashEncoder>::TethysStoreBuilder(TethysStoreBuilderParam p)
    : params(std::move(p)),
      allocator(params.graph_size(kBucketSize), kBucketSize)
{
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueEncoder,
         class StashEncoder>
void TethysStoreBuilder<PAGE_SIZE,
                        Key,
                        T,
                        TethysHasher,
                        ValueEncoder,
                        StashEncoder>::insert_list(const Key&            key,
                                                   const std::vector<T>& val)
{
    if (is_built) {
        throw std::runtime_error(
            "The Tethys builder has already been commited");
    }

    // copy the data
    data.push_back(TethysData(key, val));

    size_t value_index = data.size() - 1;

    // insert the data in the allocator
    // TethysAllocatorKey tethys_key = TethysHasher()(key);
    details::TethysAllocatorKey tethys_key
        = TethysHasher()(data[value_index].key); // avoid copies

    // we have to update the hashed key to ensure we have a bipartite graph
    size_t half_graph_size = params.graph_size(kBucketSize) / 2;
    size_t remaining_graphs_size
        = params.graph_size(kBucketSize) - half_graph_size;

    tethys_key.h[0] = tethys_key.h[0] % half_graph_size;
    tethys_key.h[1] = half_graph_size + tethys_key.h[1] % remaining_graphs_size;

    size_t list_length = val.size() + ValueEncoder::kListControlValues;

    // TODO always the same edge orientation here
    allocator.insert(tethys_key, list_length, value_index);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueEncoder,
         class StashEncoder>
void TethysStoreBuilder<PAGE_SIZE,
                        Key,
                        T,
                        TethysHasher,
                        ValueEncoder,
                        StashEncoder>::build()
{
    ValueEncoder encoder;
    StashEncoder stash_encoder;
    build(encoder, stash_encoder);
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueEncoder,
         class StashEncoder>
void TethysStoreBuilder<PAGE_SIZE,
                        Key,
                        T,
                        TethysHasher,
                        ValueEncoder,
                        StashEncoder>::build(ValueEncoder& encoder,
                                             StashEncoder& stash_encoder)
{
    if (is_built) {
        throw std::runtime_error(
            "The Tethys builder has already been commited");
    }
    size_t graph_size = params.graph_size(kBucketSize);

    abstractio::awonvm_vector<payload_type, PAGE_SIZE> tethys_table(
        params.tethys_table_path);
    tethys_table.reserve(params.graph_size(kBucketSize));

    // run the allocation algorithm
    allocator.allocate();


    // tell the encoder that we are about to start the encoding of the graph
    encoder.start_tethys_encoding(allocator.get_allocation_graph());

    for (size_t v_index = 0; v_index < graph_size; v_index++) {
        const details::Vertex& v
            = allocator.get_allocation_graph()
                  .inner_vertices()[details::VertexPtr(v_index)];

        payload_type payload;
        std::fill(payload.begin(), payload.end(), 0xFF);
        size_t written_bytes = 0;

        // declare the start of a new block to the encoder
        written_bytes += encoder.start_block_encoding(payload.data(), v_index);

        // start with incoming edges
        for (auto e_ptr : v.in_edges) {
            const auto& e = allocator.get_allocation_graph().get_edge(e_ptr);

            if (e.value_index == details::TethysAllocator::kEmptyIndexValue) {
                // this is a placeholder edge that we do not need to
                // consider
                continue;
            }

            const TethysData& d = data[e.value_index];

            size_t encoding_length
                = encoder.encode(payload.data() + written_bytes,
                                 v_index,
                                 d.key,
                                 d.values,
                                 TethysAssignmentInfo(e, IncomingEdge));

            written_bytes += encoding_length;
            if (written_bytes > sizeof(payload_type)) {
                throw std::out_of_range("Out of bound write during encoding");
            }
        }

        // then outgoing edges
        for (auto e_ptr : v.out_edges) {
            const auto& e = allocator.get_allocation_graph().get_edge(e_ptr);
            if (e.value_index == details::TethysAllocator::kEmptyIndexValue) {
                // this is a placeholder edge that we do not need to
                // consider
                continue;
            }
            const TethysData& d = data[e.value_index];

            size_t encoding_length
                = encoder.encode(payload.data() + written_bytes,
                                 v_index,
                                 d.key,
                                 d.values,
                                 TethysAssignmentInfo(e, OutgoingEdge));

            written_bytes += encoding_length;
            if (written_bytes > sizeof(payload_type)) {
                throw std::out_of_range("Out of bound write during encoding");
            }
        }

        // declare the end of the block to the encoder
        written_bytes
            += encoder.finish_block_encoding(payload.data(),
                                             v_index,
                                             written_bytes,
                                             payload.size() - written_bytes);

        if (written_bytes > sizeof(payload_type)) {
            throw std::out_of_range("Out of bound write during encoding");
        }

        size_t storage_index = tethys_table.push_back(payload);

        if (storage_index != v_index) {
            throw std::runtime_error(
                "Vertex index and storage index are offset");
        }
    }

    encoder.finish_tethys_table_encoding();

    // commit the table
    tethys_table.commit();


    // now, we have to take care of the stash
    if (allocator.get_stashed_edges().size() > 0) {
        std::ofstream stash_file;
        stash_file.open(params.tethys_stash_path);

        abstractio::
            KVSerializer<Key, TethysStashSerializationValue<T>, StashEncoder>
                serializer(stash_file);

        for (const auto& e_ptr : allocator.get_stashed_edges()) {
            const auto& e = allocator.get_allocation_graph().get_edge(e_ptr);
            if (e.value_index == details::TethysAllocator::kEmptyIndexValue) {
                // this is a placeholder edge that we do not need to
                // consider
                continue;
            }
            const TethysData&                d = data[e.value_index];
            TethysStashSerializationValue<T> v(
                &d.values,
                TethysAssignmentInfo(
                    e, IncomingEdge)); // the orientation does not matter. Yet,
                                       // we have a specified convention
            serializer.serialize(d.key, v, stash_encoder);
        }


        stash_file.close();
    }

    encoder.finish_tethys_encoding();


    is_built = true;
}

} // namespace tethys
} // namespace sse
