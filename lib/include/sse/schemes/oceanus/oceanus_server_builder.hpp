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
    struct CuckooValue
    {
        CuckooKey key;
        size_t    value_index{~0UL};
    };


    using iterator        = std::vector<CuckooValue>::iterator;
    using const_interator = std::vector<CuckooValue>::const_iterator;

    CuckooBuilder(size_t max_n_elements,
                  double epsilon,
                  size_t max_search_depth);

    static inline size_t cuckoo_table_size(size_t n_elements, double epsilon)
    {
        return std::ceil((1. + epsilon / 2.) * n_elements);
    };

    size_t cuckoo_table_size() const
    {
        return table_size;
    }

    size_t insert(const std::array<uint8_t, kTableKeySize>& key, size_t index);

    inline static constexpr bool is_empty_placeholder(size_t v)
    {
        return v == ~0UL;
    }

    const_interator table_1_begin() const
    {
        return table_1.begin();
    }
    const_interator table_1_end() const
    {
        return table_1.end();
    }
    const_interator table_2_begin() const
    {
        return table_2.begin();
    }
    const_interator table_2_end() const
    {
        return table_2.end();
    }


private:
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

    static std::string first_table_path(std::string path)
    {
        return path.append(".0");
    }
    static std::string second_table_path(std::string path)
    {
        return path.append(".1");
    }

    const std::string path;

    abstractio::awonvm_vector<content_type, PAGE_SIZE, PAGE_SIZE> data;
    // std::vector<content_type> data;

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
    : path(db_path), data(tmp_data_path(db_path)),
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
    if (is_committed) {
        return;
    }

    is_committed = true;

    // commit the data file
    data.commit();

    // create two new files: one per table

    abstractio::awonvm_vector<content_type, PAGE_SIZE> table_1(
        first_table_path(path));

    abstractio::awonvm_vector<content_type, PAGE_SIZE> table_2(
        second_table_path(path));

    table_1.reserve(cuckoo_builder.cuckoo_table_size());
    table_2.reserve(cuckoo_builder.cuckoo_table_size());

    content_type empty_content;

    memset(empty_content.data(), 0xFF, sizeof(empty_content));

    for (auto it = cuckoo_builder.table_1_begin();
         it != cuckoo_builder.table_1_end();
         ++it) {
        size_t loc = it->value_index;

        if (details::CuckooBuilder::is_empty_placeholder(loc)) {
            table_1.push_back(empty_content);
        } else {
            content_type pl = data.get(loc);
            table_1.push_back(pl);
        }
    }
    for (auto it = cuckoo_builder.table_2_begin();
         it != cuckoo_builder.table_2_end();
         ++it) {
        size_t loc = it->value_index;

        if (details::CuckooBuilder::is_empty_placeholder(loc)) {
            table_2.push_back(empty_content);
        } else {
            content_type pl = data.get(loc);
            table_2.push_back(pl);
        }
    }
    table_1.commit();
    table_2.commit();
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
