#pragma once


#include <cstdint>

#include <functional>
#include <future>

namespace sse {
namespace abstractio {

struct ReadBuffer
{
    void*  buf{nullptr};
    size_t len{0};
};

class Scheduler
{
public:
    virtual ~Scheduler() = default;

    virtual void wait_completions() = 0;

    using scheduler_callback_type = std::function<void(void*, int64_t)>;

    virtual int submit_pread(int                     fd,
                             void*                   buf,
                             size_t                  len,
                             off_t                   offset,
                             void*                   data,
                             scheduler_callback_type callback)
        = 0;
    virtual int submit_pwrite(int                     fd,
                              void*                   buf,
                              size_t                  len,
                              off_t                   offset,
                              void*                   data,
                              scheduler_callback_type callback)
        = 0;


    virtual std::future<ReadBuffer> async_read(int fd, size_t len, off_t offset)
        = 0;

    virtual std::future<int> async_write(int    fd,
                                         void*  buf,
                                         size_t len,
                                         off_t  offset)
        = 0;

    // virtual int block_pread(int fd, void* buf, size_t len, off_t offset)
    // = 0; virtual int block_pwrite(int fd, const void* buf, size_t len,
    // off_t offset) = 0;

    static size_t async_io_page_size(int fd);
};

constexpr int EINVAL_UNALIGNED_BUFFER = 1024;
constexpr int EINVAL_UNALIGNED_ACCESS = 1025;
constexpr int EINVAL_BUFFERSIZE       = 1026;
constexpr int EINVAL_INVALID_STATE    = 1027;

Scheduler* make_linux_aio_scheduler(const size_t   page_size,
                                    const unsigned n_events);
} // namespace abstractio
} // namespace sse
