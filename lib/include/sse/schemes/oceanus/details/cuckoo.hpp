#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <cmath>

#include <vector>

namespace sse {
namespace oceanus {

namespace details {

inline size_t cuckoo_table_size(size_t n_elements, double epsilon)
{
    return std::ceil((1. + epsilon / 2.) * n_elements);
};

template<size_t PAYLOAD_SIZE, size_t KEY_SIZE>
bool match_key(const std::array<uint8_t, PAYLOAD_SIZE>& pl,
               const std::array<uint8_t, KEY_SIZE>&     key)
{
    static_assert(PAYLOAD_SIZE > KEY_SIZE, "Payload too small to store a key");

    for (size_t i = 0; i < KEY_SIZE; i++) {
        if (pl[i] != key[i]) {
            return false;
        }
    }
    return true;
}

class CuckooAllocator
{
public:
    struct CuckooValue
    {
        CuckooKey key;
        size_t    value_index{~0UL};
    };


    using iterator        = std::vector<CuckooValue>::iterator;
    using const_interator = std::vector<CuckooValue>::const_iterator;

    CuckooAllocator(size_t table_size, size_t max_search_depth)
        : cuckoo_table_size(table_size), max_search_depth(max_search_depth),
          table_0(cuckoo_table_size), table_1(cuckoo_table_size)
    {
    }
    size_t get_cuckoo_table_size() const
    {
        return cuckoo_table_size;
    }

    size_t insert(const CuckooKey& key, size_t index);

    inline static constexpr bool is_empty_placeholder(size_t v)
    {
        return v == ~0UL;
    }

    const_interator table_0_begin() const
    {
        return table_0.begin();
    }
    const_interator table_0_end() const
    {
        return table_0.end();
    }
    const_interator table_1_begin() const
    {
        return table_1.begin();
    }
    const_interator table_1_end() const
    {
        return table_1.end();
    }


private:
    const size_t cuckoo_table_size;
    const size_t max_search_depth;

    std::vector<CuckooValue> table_0;
    std::vector<CuckooValue> table_1;
};

} // namespace details
} // namespace oceanus
} // namespace sse
