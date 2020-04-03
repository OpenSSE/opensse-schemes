// Append only, write once, non-volatile memory vector

#pragma once

#include <sse/schemes/abstractio/scheduler.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#include <atomic>
#include <exception>
#include <future>
#include <iostream>
#include <string>
#include <type_traits>


namespace sse {
namespace abstractio {

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT = PAGE_SIZE>
class awonvm_vector
{
    static_assert(sizeof(T) % PAGE_SIZE == 0,
                  "Incompatible type T and page size");

public:
    static constexpr size_t kTypeAlignment = ALIGNMENT;
    static constexpr size_t kPageSize      = PAGE_SIZE;

    using get_callback_type = std::function<void(std::unique_ptr<T>)>;

    awonvm_vector(const std::string& path, bool direct_io = false);
    ~awonvm_vector();

    size_t push_back(const T& val);
    size_t async_push_back(const T& val);

    void reserve(size_t n);

    void commit() noexcept;

    size_t size() const noexcept
    {
        return m_size;
    }

    T    get(size_t index);
    void async_get(size_t index, get_callback_type get_callback);

    bool is_committed() const noexcept
    {
        return m_is_committed.load();
    }

    bool use_direct_access() const noexcept
    {
        return m_use_direct_io;
    }

    void set_use_direct_access(bool flag);

private:
    const std::string  m_filename;
    int                m_fd{0};
    bool               m_use_direct_io{false};
    std::atomic_size_t m_size{0};

    std::atomic_bool m_is_committed{false};


    // std::atomic_size_t         m_completed_writes{0};
    std::unique_ptr<Scheduler> m_io_scheduler;
};

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::awonvm_vector(const std::string& path,
                                                      bool direct_io)
    : m_filename(path), m_use_direct_io(direct_io), m_io_scheduler(nullptr)
{
    // open the file at path in O_DIRECT mode
    m_fd            = utility::open_fd(path, m_use_direct_io);
    off_t file_size = utility::file_size(m_fd);

    if (file_size > 0) {
        std::cerr << "Already committed file\n";
        m_is_committed = true;

        m_size.store(file_size / sizeof(T));
    }

    if (m_use_direct_io) {
        m_io_scheduler.reset(make_linux_aio_scheduler(kPageSize, 128));
    }
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::~awonvm_vector()
{
    commit();
    close(m_fd);
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
void awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::reserve(size_t n)
{
    if (!m_is_committed && n > size()) {
        ftruncate(m_fd, n * sizeof(T));
    }
}


template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
size_t awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::push_back(const T& val)
{
    if (m_is_committed) {
        throw std::runtime_error(
            "Invalid state during write: the vector is committed");
    }

    if (m_use_direct_io && !utility::is_aligned(&val, kTypeAlignment)) {
        throw std::invalid_argument("Input is not correctly aligned");
    }

    size_t pos = m_size.fetch_add(1);
    // off_t  off = pos * sizeof(T);

    // fix issue with the alignment of val
    // int res = pwrite(m_fd, &val, sizeof(T), off);
    int res = write(m_fd, &val, sizeof(T));

    if (res != sizeof(T)) {
        std::cerr << "Error during pwrite: " << res << "\n";

        std::cerr << "errno " + std::to_string(errno) << "(" << strerror(errno)
                  << ")\n";


        throw std::runtime_error("Error during pwrite: " + std::to_string(res));
    }

    return pos;
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
size_t awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::async_push_back(const T& val)
{
    if (!m_use_direct_io) {
        std::cerr << "awonvm_vector uses buffered IOs. Calls for async IOs "
                     "will be synchronous.\n";
    }

    // we have to copy the data so it does not get destructed by the caller
    void* buf;

    int ret = posix_memalign((&buf), ALIGNMENT, std::max(ALIGNMENT, sizeof(T)));
    memcpy(buf, &val, sizeof(T));

    if (ret != 0 || buf == NULL) {
        throw std::runtime_error("Error when allocating aligned memory: errno "
                                 + std::to_string(ret) + "(" + strerror(ret)
                                 + ")");
    }

    auto cb = [](void* b, size_t /*res*/) {
        // std::cerr << (int)((uint8_t*)b)[0] << "\t" << res << "\n";
        // if (buf != b) {
        //     std::cerr << "Issue: inconsistent buffer\n";
        // }
        free(b);
        // m_completed_writes.fetch_add(1);
    };

    size_t pos = m_size.fetch_add(1);
    off_t  off = pos * sizeof(T);

    ret = m_io_scheduler->submit_pwrite(m_fd, buf, sizeof(T), off, buf, cb);

    if (ret != 1) {
        // we should have a specific exception type here to be able to return
        // which position was corrupted
        throw std::runtime_error("Error when submitting the read async IO: "
                                 + std::to_string(ret));
    }

    return pos;
}


template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
void awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::commit() noexcept
{
    if (!m_is_committed) {
        if (m_use_direct_io) {
            m_io_scheduler.reset(make_linux_aio_scheduler(
                kPageSize,
                128)); // this will block until the completion of write
            // queries and then create a new scheduler for future
            // async read queries
        } else {
            fsync(m_fd);
        }
    }
    m_is_committed = true;
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
void awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::set_use_direct_access(bool flag)
{
    if (flag != m_use_direct_io) {
        // wait for unfinished async IOs
        m_io_scheduler.reset(nullptr);

        // close the current file descriptor
        close(m_fd);

        // reopen a file descriptor
        m_fd = utility::open_fd(m_filename, flag);


        // recreate an async scheduler
        m_io_scheduler.reset(make_linux_aio_scheduler(
            kPageSize,
            128)); // this will block until the completion of write

        m_use_direct_io = flag;
    }
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
T awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::get(size_t index)
{
    if (index > m_size.load()) {
        throw std::invalid_argument("Index (" + std::to_string(index)
                                    + ") out of bounds (size="
                                    + std::to_string(m_size.load()) + ")");
    }

    if (!m_is_committed) {
        throw std::runtime_error(
            "Invalid state during read: the vector is not committed");
    }

    alignas(kTypeAlignment) T v;

    int res = pread(m_fd, &v, sizeof(T), index * sizeof(T));

    if (res != sizeof(T)) {
        std::cerr << "Error during pread: " << res << "\n";
        throw std::runtime_error("Error during pread: " + std::to_string(res));
    }

    return v;
}

template<typename T, size_t PAGE_SIZE, size_t ALIGNMENT>
void awonvm_vector<T, PAGE_SIZE, ALIGNMENT>::async_get(
    size_t            index,
    get_callback_type get_callback)
{
    if (index > m_size.load()) {
        throw std::invalid_argument("Index (" + std::to_string(index)
                                    + ") out of bounds (size="
                                    + std::to_string(m_size.load()) + ")");
    }

    if (!m_is_committed) {
        throw std::runtime_error(
            "Invalid state during read: the vector is not committed");
    }

    if (!m_use_direct_io) {
        std::cerr << "awonvm_vector uses buffered IOs. Calls for async IOs "
                     "will be synchronous.\n";
    }

    void* buffer;
    int   ret
        = posix_memalign((&buffer), ALIGNMENT, std::max(ALIGNMENT, sizeof(T)));

    if (ret != 0 || buffer == NULL) {
        throw std::runtime_error("Error when allocating aligned memory: errno "
                                 + std::to_string(ret) + "(" + strerror(ret)
                                 + ")");
    }

    auto inner_cb = [get_callback](void* buf, int64_t res) {
        std::unique_ptr<T> result(nullptr);

        if (res == sizeof(T)) {
            result.reset(reinterpret_cast<T*>(buf));
        }

        get_callback(std::move(result));
    };

    ret = m_io_scheduler->submit_pread(
        m_fd, buffer, sizeof(T), index * sizeof(T), buffer, inner_cb);

    if (ret != 1) {
        free(buffer);

        throw std::runtime_error(
            "Error when submitting the read async IO: errno "
            + std::to_string(ret) + "(" + strerror(ret) + ")");
    }
}

} // namespace abstractio
} // namespace sse
