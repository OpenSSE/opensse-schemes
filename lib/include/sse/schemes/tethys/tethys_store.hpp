
#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/tethys/details/tethys_allocator.hpp>

#include <array>
#include <string>
#include <vector>

namespace sse {
namespace tethys {

struct TethysStoreBuilderParam
{
    // std::string value_file_path;
    std::string tethys_table_path;

    size_t max_n_elements;
    double epsilon;

    size_t graph_size() const
    {
        return details::tethys_graph_size(max_n_elements, epsilon);
    }
};

enum TethysAssignmentEdgeOrientation : uint8_t
{
    IncomingEdge = 0,
    OutgoingEdge
};
struct TethysAssignmentInfo
{
    size_t                          list_length;
    size_t                          assigned_list_length;
    size_t                          dual_assigned_list_length;
    TethysAssignmentEdgeOrientation edge_orientation;

    TethysAssignmentInfo(const details::Edge&            e,
                         TethysAssignmentEdgeOrientation o)
        : list_length(e.capacity), edge_orientation(o)
    {
        if (edge_orientation == OutgoingEdge) {
            assigned_list_length      = e.flow;
            dual_assigned_list_length = e.rec_flow;
        } else {
            assigned_list_length      = e.rec_flow;
            dual_assigned_list_length = e.flow;
        }
    }
};
template<size_t PAGE_SIZE,
         class Key,
         class T,
         class ValueEncoder,
         class TethysHasher>
class TethysStoreBuilder
{
public:
    static constexpr size_t kPayloadSize = PAGE_SIZE;
    using payload_type                   = std::array<uint8_t, kPayloadSize>;


    explicit TethysStoreBuilder(TethysStoreBuilderParam p);

    void insert_list(const Key& key, const std::vector<T>& val);

    typename std::enable_if<
        std::is_default_constructible<ValueEncoder>::value>::type
    build()
    {
        ValueEncoder encoder;
        build(encoder);
    }

    void build(ValueEncoder& encoder);

private:
    struct TethysData
    {
        const Key            key;
        const std::vector<T> values;

        TethysData(Key k, std::vector<T> v)
            : key(std::move(k)), values(std::move(v))
        {
        }
    };

    TethysStoreBuilderParam  params;
    details::TethysAllocator allocator;
    std::vector<TethysData>  data;

    size_t n_elements;
    bool   is_built{false};
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class ValueEncoder,
         class TethysHasher>
TethysStoreBuilder<PAGE_SIZE, Key, T, ValueEncoder, TethysHasher>::
    TethysStoreBuilder(TethysStoreBuilderParam p)
    : params(std::move(p)),
      allocator(params.graph_size(), PAGE_SIZE / sizeof(T))
{
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class ValueEncoder,
         class TethysHasher>
void TethysStoreBuilder<PAGE_SIZE, Key, T, ValueEncoder, TethysHasher>::
    insert_list(const Key& key, const std::vector<T>& val)
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
    size_t half_graph_size       = params.graph_size() / 2;
    size_t remaining_graphs_size = params.graph_size() - half_graph_size;

    tethys_key.h[0] = tethys_key.h[0] % half_graph_size;
    tethys_key.h[1] = half_graph_size + tethys_key.h[1] % remaining_graphs_size;

    size_t list_length = val.size() + ValueEncoder::kControlBlockSizeEntries;

    // TODO always the same edge orientation here
    allocator.insert(tethys_key, list_length, value_index);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class ValueEncoder,
         class TethysHasher>
void TethysStoreBuilder<PAGE_SIZE, Key, T, ValueEncoder, TethysHasher>::build(
    ValueEncoder& encoder)
{
    if (is_built) {
        throw std::runtime_error(
            "The Tethys builder has already been commited");
    }
    size_t graph_size = params.graph_size();

    abstractio::awonvm_vector<payload_type, PAGE_SIZE> tethys_table(
        params.tethys_table_path);
    tethys_table.reserve(params.graph_size());

    // run the allocation algorithm
    allocator.allocate();

    is_built = true;

    for (size_t v_index = 0; v_index < graph_size; v_index++) {
        const details::Vertex& v
            = allocator.get_allocation_graph()
                  .inner_vertices()[details::VertexPtr(v_index)];

        payload_type payload;
        std::fill(payload.begin(), payload.end(), 0xFF);
        size_t written_bytes = 0;

        // start with incoming edges
        for (auto e_ptr : v.in_edges) {
            const auto& e = allocator.get_allocation_graph().get_edge(e_ptr);

            if (e.value_index == details::TethysAllocator::kEmptyIndexValue) {
                // this is a placeholder edge that we do not need to consider
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
                // this is a placeholder edge that we do not need to consider
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


        size_t storage_index = tethys_table.push_back(payload);

        if (storage_index != v_index) {
            throw std::runtime_error(
                "Vertex index and storage index are offset");
        }
    }

    // commit the table
    tethys_table.commit();

    // now, we have to take care of the stash
    if (allocator.get_stashed_edges().size() > 0) {
        std::cerr << "You are going to lose some data: stash storage is still "
                     "unimplemented.\n";
    }
}

} // namespace tethys


} // namespace sse
