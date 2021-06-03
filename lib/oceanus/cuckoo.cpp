#include <sse/schemes/oceanus/cuckoo.hpp>

#include <utility>

namespace sse {
namespace oceanus {
namespace details {


size_t CuckooAllocator::insert(const CuckooKey& key, size_t index)

{
    using std::swap;

    if (index == ~0UL) {
        throw std::invalid_argument("Index must be different from -1");
    }

    CuckooValue value;

    value.key         = key;
    value.value_index = index;

    unsigned                                 table_index = 0;
    std::array<std::vector<CuckooValue>*, 2> tables      = {&table_0, &table_1};

    // search for an empty space
    for (size_t depth = 0; (depth < max_search_depth)
                           && (!is_empty_placeholder(value.value_index));
         depth++) {
        size_t loc = value.key.h[table_index] % cuckoo_table_size;

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
