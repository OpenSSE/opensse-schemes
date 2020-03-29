#include <sse/schemes/oceanus/oceanus_server_builder.hpp>

#include <utility>

namespace sse {
namespace oceanus {
namespace details {


CuckooBuilder::CuckooBuilder(size_t max_n_elements,
                             double epsilon,
                             size_t max_search_depth)
    : table_size(cuckoo_table_size(max_n_elements, epsilon)),
      table_1(table_size), table_2(table_size),
      max_search_depth(max_search_depth)
{
}


size_t CuckooBuilder::insert(const std::array<uint8_t, kTableKeySize>& key,
                             size_t                                    index)
{
    using std::swap;

    if (index == ~0UL) {
        throw std::invalid_argument("Index must be different from -1");
    }

    CuckooValue value;

    value.key         = *reinterpret_cast<const CuckooKey*>(key.data());
    value.value_index = index;

    unsigned                                 table_index = 0;
    std::array<std::vector<CuckooValue>*, 2> tables      = {&table_1, &table_2};

    // search for an empty space
    for (size_t depth = 0;
         (depth < max_search_depth) && (value.value_index != ~0UL);
         depth++) {
        size_t loc = value.key.h[table_index] % table_size;

        swap(value, (*tables[table_index])[loc]);

        // go to the other table for the next iteration:
        // if the bucket was empty, the loop will stop,
        // otherwise we would have to switch the table

        table_index = (table_index == 0) ? 1 : 0;
    }


    return value.value_index;
}

} // namespace details
} // namespace oceanus
} // namespace sse
