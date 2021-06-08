#pragma once


#include <cstdint>

#include <functional>
#include <future>
#include <vector>

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

    struct PReadSumission
    {
        int                     fd;
        void*                   buf;
        size_t                  len;
        size_t                  offset;
        void*                   data;
        scheduler_callback_type callback;
        PReadSumission(int                     fd,
                       void*                   buf,
                       size_t                  len,
                       size_t                  offset,
                       void*                   data,
                       scheduler_callback_type callback)
            : fd(fd), buf(buf), len(len), offset(offset), data(data),
              callback(std::move(callback))
        {
        }
    };


    virtual int submit_pread(int                     fd,
                             void*                   buf,
                             size_t                  len,
                             off_t                   offset,
                             void*                   data,
                             scheduler_callback_type callback)
        = 0;

    inline virtual int submit_preads(const std::vector<PReadSumission>& subs);

    virtual int submit_pwrite(int                     fd,
                              void*                   buf,
                              size_t                  len,
                              off_t                   offset,
                              void*                   data,
                              scheduler_callback_type callback)
        = 0;


    // virtual std::future<ReadBuffer> async_read(int fd, size_t len, off_t
    // offset)
    //     = 0;

    // virtual std::future<int> async_write(int    fd,
    //                                      void*  buf,
    //                                      size_t len,
    //                                      off_t  offset)
    //     = 0;

    // virtual int block_pread(int fd, void* buf, size_t len, off_t offset)
    // = 0; virtual int block_pwrite(int fd, const void* buf, size_t len,
    // off_t offset) = 0;

    static size_t async_io_page_size(int fd);
};

int Scheduler::submit_preads(const std::vector<PReadSumission>& subs)
{
    int ret = 0;
    for (const auto& read : subs) {
        int err = this->submit_pread(
            read.fd, read.buf, read.len, read.offset, read.data, read.callback);

        if (err == 1) {
            ret++;
        }
    }
    return ret;
}
constexpr int EINVAL_UNALIGNED_BUFFER = 1024;
constexpr int EINVAL_UNALIGNED_ACCESS = 1025;
constexpr int EINVAL_BUFFERSIZE       = 1026;
constexpr int EINVAL_INVALID_STATE    = 1027;

#ifdef HAS_LIBAIO
Scheduler* make_linux_aio_scheduler(const size_t   page_size,
                                    const unsigned n_events);
#endif

Scheduler* make_thread_pool_aio_scheduler();


Scheduler* make_default_aio_scheduler(const size_t page_size);

} // namespace abstractio
} // namespace sse
