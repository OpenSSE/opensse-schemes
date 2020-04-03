#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <cmath>

#include <vector>

namespace sse {
namespace oceanus {
namespace details {
class CuckooBuilder
{
public:
    CuckooBuilder(size_t max_n_elements,
                  double epsilon,
                  size_t max_search_depth);

    static inline size_t cuckoo_table_size(size_t n_elements, double epsilon)
    {
        return std::ceil((2. + epsilon) * n_elements);
    };

    size_t insert(const std::array<uint8_t, kTableKeySize>& key, size_t index);

    inline static constexpr bool is_empty_placeholder(size_t v)
    {
        return v == ~0UL;
    }

private:
    struct CuckooValue
    {
        CuckooKey key;
        size_t    value_index{~0UL};
    };
    // friend void swap(CuckooValue& lhs, CuckooValue& rhs);


    const size_t table_size;


    std::vector<CuckooValue> table_1;
    std::vector<CuckooValue> table_2;

    const size_t max_search_depth;
};
} // namespace details


template<size_t PAGE_SIZE>
class OceanusServerBuilder
{
public:
    OceanusServerBuilder(const std::string& db_path,
                         size_t             max_n_elements,
                         double             epsilon,
                         size_t             max_search_depth);
    ~OceanusServerBuilder();


    void insert(const std::array<uint8_t, kTableKeySize>& key,
                const data_type<PAGE_SIZE>&               value);

    void commit();


private:
    // struct Content
    // {
    //     // std::array<uint8_t, kTableKeySize> key;
    //     payload_type<PAGE_SIZE> value;

    //     Content() = default;
    //     // Content(std::array<uint8_t, kTableKeySize> k,
    //     payload_type<PAGE_SIZE>
    //     // v) : key(std::move(k)), value(std::move(v))
    //     // {
    //     // }

    //     Content(payload_type<PAGE_SIZE> v) : value(std::move(v))
    //     {
    //     }
    // };

    using content_type = payload_type<PAGE_SIZE>;

    static std::string tmp_data_path(std::string path)
    {
        return path.append(".tmp");
    }

    // abstractio::awonvm_vector<content_type, PAGE_SIZE, true> data;
    std::vector<content_type> data;

    details::CuckooBuilder cuckoo_builder;
    std::vector<size_t>    spilled_data;

    const size_t      max_n_elements;
    const std::string db_path;
    size_t            n_elements;


    bool is_committed{false};
};


template<size_t PAGE_SIZE>
OceanusServerBuilder<PAGE_SIZE>::OceanusServerBuilder(
    const std::string& db_path,
    size_t             max_n_elements,
    double             epsilon,
    size_t             max_search_depth)
    : data(/*tmp_data_path(db_path)*/),
      cuckoo_builder(max_n_elements, epsilon, max_search_depth), spilled_data(),
      max_n_elements(max_n_elements), db_path(db_path), n_elements(0)
{
    data.reserve(max_n_elements);
}

template<size_t PAGE_SIZE>
OceanusServerBuilder<PAGE_SIZE>::~OceanusServerBuilder()
{
    if (!is_committed) {
        commit();
    }
}


template<size_t PAGE_SIZE>
void OceanusServerBuilder<PAGE_SIZE>::commit()
{
}

template<size_t PAGE_SIZE>
void OceanusServerBuilder<PAGE_SIZE>::insert(
    const std::array<uint8_t, kTableKeySize>& key,
    const data_type<PAGE_SIZE>&               value)
{
    payload_type<PAGE_SIZE> payload;

    memcpy(payload.data(), key.data(), kTableKeySize);
    std::copy(value.begin(), value.end(), payload.begin() + kOverhead);

    // data.emplace_back(std::move(value));
    data.push_back(payload);

    size_t spill = cuckoo_builder.insert(key, data.size() - 1);

    if (!details::CuckooBuilder::is_empty_placeholder(spill)) {
        std::cerr << "Spill!\n";
        spilled_data.push_back(spill);
    } else {
        // std::cerr << "No spill\n";
    }
}

} // namespace oceanus
} // namespace sse
