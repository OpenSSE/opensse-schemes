//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#pragma once

#include <cstdint>
#include <sys/stat.h>

#include <array>
#include <iomanip>
#include <sstream>
#include <string>

namespace sse {
namespace utility {

template<size_t N>
uint64_t xor_mask(const uint64_t in, const std::array<uint8_t, N>& mask)
{
    static_assert(N >= 8, "Input array is too small.");

    // Defined for LITTLE ENDIAN arch
    return in ^ (static_cast<uint64_t>(mask[0]) << 56)
           ^ (static_cast<uint64_t>(mask[1]) << 48)
           ^ (static_cast<uint64_t>(mask[2]) << 40)
           ^ (static_cast<uint64_t>(mask[3]) << 32)
           ^ (static_cast<uint64_t>(mask[4]) << 24)
           ^ (static_cast<uint64_t>(mask[5]) << 16)
           ^ (static_cast<uint64_t>(mask[6]) << 8)
           ^ (static_cast<uint64_t>(mask[7]));
}


bool is_file(const std::string& path);
bool is_directory(const std::string& path);
bool exists(const std::string& path);
bool create_directory(const std::string& path, mode_t mode);
bool remove_directory(const std::string& path);
bool remove_file(const std::string& path);

int     open_fd(const std::string& filename, bool direct_io);
ssize_t file_size(int fd);

std::string hex_string(const std::string& in);

// template<size_t N>
// std::string hex_string(const std::array<uint8_t, N>& in)
// {
//     std::ostringstream out;
//     for (unsigned char c : in) {
//         out << std::hex << std::setw(2) << std::setfill('0')
//             << static_cast<uint>(c);
//     }
//     return out.str();
// }

template<typename T, size_t N>
std::string hex_string(const std::array<T, N>& in)
{
    std::ostringstream out;
    for (unsigned char c : in) {
        out << std::hex << std::setw(2 * sizeof(T)) << std::setfill('0')
            << static_cast<uint64_t>(c);
    }
    return out.str();
}

std::ostream& print_hex(std::ostream& out, const std::string& s);
template<size_t N>
std::ostream& print_hex(std::ostream& out, const std::array<uint8_t, N>& a)
{
    for (unsigned char c : a) {
        out << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<uint>(c);
    }
    return out;
}

std::string hex_string(const uint64_t& a);
std::string hex_string(const uint32_t& a);

template<typename T>
constexpr auto is_aligned(T x, size_t a) noexcept ->
    typename std::enable_if<std::is_integral<T>::value
                                && !std::is_same<T, bool>::value,
                            bool>::type
{
    return (x & (a - 1)) == 0;
}

inline bool is_aligned(const volatile void* p, size_t a)
{
    return is_aligned(reinterpret_cast<uintptr_t>(p), a);
}


size_t os_page_size();
size_t device_page_size(int fd);
size_t device_page_size(const std::string& path);

} // namespace utility
} // namespace sse