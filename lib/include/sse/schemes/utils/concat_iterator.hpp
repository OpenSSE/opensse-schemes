#pragma once

namespace sse {
namespace utility {

template<class Container>
class concat_iterator
{
public:
    using value_type      = typename Container::value_type;
    using size_type       = typename Container::size_type;
    using difference_type = typename Container::difference_type;
    using reference       = value_type&;
    using const_reference = const value_type&;
    using pointer         = value_type*;
    using const_pointer   = const value_type*;

    using container_iterator = typename Container::iterator;

    concat_iterator& operator++()
    {
        ++internal_iterator;
        if (!point_to_container_2 && internal_iterator == container_1->end()) {
            internal_iterator    = container_2->begin();
            point_to_container_2 = true;
        }
        return *this;
    }

    // It is fine to return a non-const iterator as they can point to
    // non-temporary objects
    // NOLINTNEXTLINE(cert-dcl21-cpp)
    concat_iterator operator++(int)
    {
        concat_iterator retval = *this;
        ++(*this);
        return retval;
    }
    bool operator==(const concat_iterator& other) const
    {
        return internal_iterator == other.internal_iterator;
    }
    bool operator!=(const concat_iterator& other) const
    {
        return !(*this == other);
    }
    reference operator*() const
    {
        return *internal_iterator;
    }

    concat_iterator(Container& c1, Container& c2)
        : container_1(&c1), container_2(&c2), internal_iterator(c1.begin()),
          point_to_container_2(false)
    {
    }

    concat_iterator(Container&         c1,
                    Container&         c2,
                    container_iterator it,
                    bool               it_points_c2)
        : container_1(&c1), container_2(&c2), internal_iterator(it),
          point_to_container_2(it_points_c2)
    {
    }

private:
    Container* container_1;
    Container* container_2;

    container_iterator internal_iterator;
    bool               point_to_container_2;
};


// for const-correctness, we need a second class for const iterators
// ... and code duplication

template<class Container>
class concat_const_iterator
{
public:
    using value_type      = typename Container::value_type;
    using size_type       = typename Container::size_type;
    using difference_type = typename Container::difference_type;
    using reference       = value_type&;
    using const_reference = const value_type&;
    using pointer         = value_type*;
    using const_pointer   = const value_type*;

    using container_iterator = typename Container::const_iterator;

    concat_const_iterator& operator++()
    {
        ++internal_iterator;
        if (!point_to_container_2 && internal_iterator == container_1->end()) {
            internal_iterator    = container_2->begin();
            point_to_container_2 = true;
        }
        return *this;
    }

    // It is fine to return a non-const iterator as they can point to
    // non-temporary objects
    // NOLINTNEXTLINE(cert-dcl21-cpp)
    concat_const_iterator operator++(int)
    {
        concat_const_iterator retval = *this;
        ++(*this);
        return retval;
    }
    bool operator==(const concat_const_iterator& other) const
    {
        return internal_iterator == other.internal_iterator;
    }
    bool operator!=(const concat_const_iterator& other) const
    {
        return !(*this == other);
    }
    const_reference operator*() const
    {
        return *internal_iterator;
    }

    concat_const_iterator(const Container& c1, const Container& c2)
        : container_1(&c1), container_2(&c2), internal_iterator(c1.begin()),
          point_to_container_2(false)
    {
    }

    concat_const_iterator(const Container&   c1,
                          const Container&   c2,
                          container_iterator it,
                          bool               it_points_c2)
        : container_1(&c1), container_2(&c2), internal_iterator(it),
          point_to_container_2(it_points_c2)
    {
    }

private:
    const Container* container_1;
    const Container* container_2;

    container_iterator internal_iterator;
    bool               point_to_container_2;
};

} // namespace utility
} // namespace sse