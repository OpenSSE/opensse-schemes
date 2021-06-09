// Append only, write once, non-volatile memory vector

#pragma once

#include <sse/schemes/abstractio/scheduler.hpp>
#include <sse/schemes/utils/logger.hpp>
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

template<typename T, size_t ALIGNMENT = alignof(T)>
class awonvm_vector
{
public:
    static constexpr size_t kTypeAlignment = ALIGNMENT;
    static constexpr size_t kValueSize     = sizeof(T);

    static_assert(kTypeAlignment <= kValueSize,
                  "Invalid alignment for the type size");

    using get_callback_type = std::function<void(std::unique_ptr<T>)>;

    struct GetRequest
    {
        size_t            index;
        get_callback_type callback;

        GetRequest(size_t index, get_callback_type callback)
            : index(index), callback(std::move(callback))
        {
        }
    };

    // cppcheck-suppress noExplicitConstructor
    awonvm_vector(const std::string&           path,
                  std::unique_ptr<Scheduler>&& scheduler,
                  bool                         direct_io);
    explicit awonvm_vector(const std::string& path, bool direct_io = false);
    ~awonvm_vector();

    awonvm_vector(awonvm_vector&& vec) noexcept;

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
    void async_gets(const std::vector<GetRequest>& requests);

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
    static size_t async_io_page_size(int fd);


    const std::string m_filename;
    bool              m_use_direct_io{false};
    int               m_fd{0};
    const size_t      m_device_page_size;

    std::atomic_size_t m_size{0};

    std::atomic<bool> m_is_committed{false};

    std::unique_ptr<Scheduler> m_io_scheduler;
    bool                       m_io_warn_flag{false};
};
template<typename T, size_t ALIGNMENT>
constexpr size_t awonvm_vector<T, ALIGNMENT>::kValueSize;

template<typename T, size_t ALIGNMENT>
// cppcheck-suppress uninitMemberVar
// false positive
awonvm_vector<T, ALIGNMENT>::awonvm_vector(
    const std::string&           path,
    std::unique_ptr<Scheduler>&& scheduler,
    bool                         direct_io)
    : m_filename(path), m_use_direct_io(direct_io),
      m_fd(utility::open_fd(path, m_use_direct_io)),
      m_device_page_size(Scheduler::async_io_page_size(m_fd)),
      m_io_scheduler(std::move(scheduler))
{
    off_t file_size = utility::file_size(m_fd);

    if (m_device_page_size == 0) {
        sse::logger::logger()->warn(
            "Unable to read page size for file {}. Async IOs will "
            "most likely be blocking.");
    } else if (kValueSize % m_device_page_size != 0) {
        sse::logger::logger()->warn("Device page size for file {} ({} "
                                    "bytes) is not aligned with the "
                                    "value size ({} bytes). Async IOs will "
                                    "most likely be blocking.",
                                    path,
                                    m_device_page_size,
                                    kValueSize);
    }


    if (file_size > 0) {
        m_is_committed = true;

        m_size.store(file_size / sizeof(T));
    }
}

template<typename T, size_t ALIGNMENT>
// cppcheck-suppress uninitMemberVar
// false positive
awonvm_vector<T, ALIGNMENT>::awonvm_vector(const std::string& path,
                                           bool               direct_io)
    : m_filename(path), m_use_direct_io(direct_io),
      m_fd(utility::open_fd(path, m_use_direct_io)),
      m_device_page_size(Scheduler::async_io_page_size(m_fd)),
      m_io_scheduler(make_default_aio_scheduler(m_device_page_size))
{
    off_t file_size = utility::file_size(m_fd);

    if (m_device_page_size == 0) {
        sse::logger::logger()->warn(
            "Unable to read page size for file {}. Async IOs will "
            "most likely be blocking.");
    } else if (kValueSize % m_device_page_size != 0) {
        sse::logger::logger()->warn("Device page size for file {} ({} "
                                    "bytes) is not aligned with the "
                                    "value size ({} bytes). Async IOs will "
                                    "most likely be blocking.",
                                    path,
                                    m_device_page_size,
                                    kValueSize);
    }


    if (file_size > 0) {
        m_is_committed = true;

        m_size.store(file_size / sizeof(T));
    }
}
template<typename T, size_t ALIGNMENT>
awonvm_vector<T, ALIGNMENT>::awonvm_vector(awonvm_vector&& vec) noexcept
    : m_filename(vec.m_filename), m_use_direct_io(vec.m_use_direct_io),
      m_fd(vec.m_fd), m_device_page_size(vec.m_device_page_size),
      m_io_scheduler(std::move(vec.m_io_scheduler))
{
    vec.m_fd = 0;
}

template<typename T, size_t ALIGNMENT>
awonvm_vector<T, ALIGNMENT>::~awonvm_vector()
{
    if (!m_is_committed) {
        commit();
    } else {
        if (m_io_scheduler) {
            m_io_scheduler->wait_completions();
        }
    }
    close(m_fd);
}

template<typename T, size_t ALIGNMENT>
void awonvm_vector<T, ALIGNMENT>::reserve(size_t n)
{
    if (!m_is_committed && n > size()) {
        int ret = ftruncate(m_fd, n * sizeof(T));
        if (ret != 0) {
            sse::logger::logger()->warn(
                "Unable to reserver space for "
                "awonvm_vector. ftrunctate returned {}. Error: {}",
                ret,
                strerror(errno));
        }
    }
}


template<typename T, size_t ALIGNMENT>
size_t awonvm_vector<T, ALIGNMENT>::push_back(const T& val)
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

template<typename T, size_t ALIGNMENT>
size_t awonvm_vector<T, ALIGNMENT>::async_push_back(const T& val)
{
    if (!m_io_scheduler) {
        throw std::runtime_error("No IO Scheduler set");
    }

    if (!m_use_direct_io && !m_io_warn_flag) {
        std::cerr << "awonvm_vector uses buffered IOs. Calls for async IOs "
                     "will be synchronous.\n";
        m_io_warn_flag = true;
    }

    // we have to copy the data so it does not get destructed by the caller
    void* buf;

    int ret = posix_memalign((&buf), ALIGNMENT, std::max(ALIGNMENT, sizeof(T)));

    if (ret != 0 || buf == nullptr) {
        throw std::runtime_error("Error when allocating aligned memory: errno "
                                 + std::to_string(ret) + "(" + strerror(ret)
                                 + ")");
    }
    memcpy(buf, &val, sizeof(T));

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


template<typename T, size_t ALIGNMENT>
void awonvm_vector<T, ALIGNMENT>::commit() noexcept
{
    if (!m_is_committed) {
        if (m_io_scheduler) {
            m_io_scheduler->wait_completions();
            Scheduler* new_sched = m_io_scheduler->duplicate();
            m_io_scheduler.reset(
                new_sched); // this will block until the completion of write
                            // queries and then create a new scheduler for
                            // future async read queries
        } else {
            fsync(m_fd);
        }
    }
    m_is_committed = true;
}

template<typename T, size_t ALIGNMENT>
void awonvm_vector<T, ALIGNMENT>::set_use_direct_access(bool flag)
{
    if (flag != m_use_direct_io) {
        // wait for unfinished async IOs
        m_io_scheduler->wait_completions();

        // close the current file descriptor
        close(m_fd);

        // reopen a file descriptor
        m_fd = utility::open_fd(m_filename, flag);


        // recreate an async scheduler
        Scheduler* new_sched = m_io_scheduler->duplicate();
        m_io_scheduler.reset(new_sched);

        m_use_direct_io = flag;
        m_io_warn_flag  = false;
    }
}

template<typename T, size_t ALIGNMENT>
T awonvm_vector<T, ALIGNMENT>::get(size_t index)
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

template<typename T, size_t ALIGNMENT>
void awonvm_vector<T, ALIGNMENT>::async_get(size_t            index,
                                            get_callback_type get_callback)
{
    if (!m_io_scheduler) {
        throw std::runtime_error("No IO Scheduler set");
    }

    if (!m_is_committed) {
        throw std::runtime_error(
            "Invalid state during read: the vector is not committed");
    }

    if (!m_use_direct_io && !m_io_warn_flag) {
        std::cerr << "awonvm_vector uses buffered IOs. Calls for async IOs "
                     "will be synchronous.\n";
        m_io_warn_flag = true;
    }

    if (index > m_size.load()) {
        throw std::invalid_argument("Index (" + std::to_string(index)
                                    + ") out of bounds (size="
                                    + std::to_string(m_size.load()) + ")");
    }

    void* buffer;
    int   ret
        = posix_memalign((&buffer), ALIGNMENT, std::max(ALIGNMENT, sizeof(T)));

    if (ret != 0 || buffer == nullptr) {
        throw std::runtime_error("Error when allocating aligned memory: errno "
                                 + std::to_string(ret) + "(" + strerror(ret)
                                 + ")");
    }

    auto inner_cb = [get_callback](void* buf, int64_t res) {
        std::unique_ptr<T> result(nullptr);

        if (res == sizeof(T)) {
            result.reset(reinterpret_cast<T*>(buf));
        } else {
            free(buf); // avoid memory leaks
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

template<typename T, size_t ALIGNMENT>
void awonvm_vector<T, ALIGNMENT>::async_gets(
    const std::vector<GetRequest>& requests)
{
    if (!m_io_scheduler) {
        throw std::runtime_error("No IO Scheduler set");
    }

    if (!m_is_committed) {
        throw std::runtime_error(
            "Invalid state during read: the vector is not committed");
    }

    if (!m_use_direct_io && !m_io_warn_flag) {
        std::cerr << "awonvm_vector uses buffered IOs. Calls for async IOs "
                     "will be synchronous.\n";
        m_io_warn_flag = true;
    }

    std::vector<Scheduler::PReadSumission> submissions;
    submissions.reserve(requests.size());

    for (const auto& req : requests) {
        if (req.index > m_size.load()) {
            throw std::invalid_argument("Index (" + std::to_string(req.index)
                                        + ") out of bounds (size="
                                        + std::to_string(m_size.load()) + ")");
        }


        void* buffer;
        int   ret = posix_memalign(
            (&buffer), ALIGNMENT, std::max(ALIGNMENT, sizeof(T)));

        if (ret != 0 || buffer == nullptr) {
            throw std::runtime_error(
                "Error when allocating aligned memory: errno "
                + std::to_string(ret) + "(" + strerror(ret) + ")");
        }

        auto get_callback = req.callback;
        auto inner_cb     = [get_callback](void* buf, int64_t res) {
            std::unique_ptr<T> result(nullptr);

            if (res == sizeof(T)) {
                result.reset(reinterpret_cast<T*>(buf));
            }

            get_callback(std::move(result));
        };

        submissions.push_back(Scheduler::PReadSumission(
            m_fd, buffer, sizeof(T), req.index * sizeof(T), buffer, inner_cb));
    }

    int ret = m_io_scheduler->submit_preads(submissions);

    if (ret < 0 || static_cast<size_t>(ret) != submissions.size()) {
        for (auto& sub : submissions) {
            free(sub.buf);
        }

        throw std::runtime_error(
            "Error when submitting the read async IO: errno "
            + std::to_string(ret) + "(" + strerror(ret) + ")");
    }
}


} // namespace abstractio
} // namespace sse
