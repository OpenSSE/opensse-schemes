#pragma once

#include <sse/configure.hpp>

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


/// Scheduler abstract class.
///
/// This class describes the interface of asynchronous IO schedulers. These are
/// objects to which we can post IO queries, together with a callback. The
/// scheduler will return immediately from the post call, and use the callback
/// to notify the originating code from the completion of the query.
///
/// IMPORTANT INVARIANTS
///
/// The following invariants are not (and for some of them cannot be) verified
/// at runtime. Not respecting them can lead to undefined behaviors (or worse,
/// concurrency bugs).
/// 1. Once `wait_completions()`, new queries are not expected to be posted.
/// 2. The caller is ALWAYS responsible of destroying the memory buffers passed
/// in the post calls.
/// 3. The callbacks are passed the `data` pointer given by the caller at
/// posting time, not the read or write buffer. If you want to get that buffer
/// when called back, just use the pointer twice in the post call.
/// 4. The other value returned by the callback is the number of read/written
/// bytes.
/// 5. The callbacks passed in the post calls are run on the scheduler's
/// thread(s). Running a time-consuming operation in this callback is not
/// recommended as it might reduce the IO latency and throughput.
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


    virtual Scheduler* duplicate() const = 0;

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
