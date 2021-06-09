#include "thread_pool_aio_scheduler.hpp"

#include "utils/thread_pool.hpp"

#include <sse/schemes/utils/logger.hpp>

#include <cstring>
#include <unistd.h>

#include <thread>


namespace sse {
namespace abstractio {

static ThreadPool* _shared_io_pool = nullptr;

constexpr uint32_t kAIOThreadsCount = 50;

static ThreadPool& get_shared_io_pool()
{
    if (_shared_io_pool == nullptr) {
        _shared_io_pool = new ThreadPool(kAIOThreadsCount);
    }
    return *_shared_io_pool;
}

ThreadPoolAIOScheduler::~ThreadPoolAIOScheduler()
{
    ThreadPoolAIOScheduler::wait_completions();
}

void ThreadPoolAIOScheduler::wait_completions()
{
    while (this->m_running_queries != 0) {
        std::unique_lock<std::mutex> lock(m_cv_lock);
        m_cv_submission.wait(lock,
                             [this] { return this->m_running_queries == 0; });
    }
}

int ThreadPoolAIOScheduler::submit_pread(int                     fd,
                                         void*                   buf,
                                         size_t                  len,
                                         off_t                   offset,
                                         void*                   data,
                                         scheduler_callback_type callback)
{
    auto task = [this, fd, buf, len, offset, data, callback]() {
        ssize_t ret = pread(fd, buf, len, offset);
        if (ret == -1) {
            sse::logger::logger()->error("Unable to complete the positioned "
                                         "read. pread returned {}. Error: {}",
                                         ret,
                                         strerror(errno));
        } else if (static_cast<size_t>(ret) < len) {
            sse::logger::logger()->warn(
                "Incomplete pread: {} instead of {}", ret, len);
        }
        callback(data, ret);

        std::unique_lock<std::mutex> lock(
            this->m_cv_lock); // we use a lock here to avoid TOCTOU bugs

        this->m_running_queries--;
        this->m_cv_submission.notify_all();
    };

    m_running_queries++;
    get_shared_io_pool().enqueue(task);

    return 1;
}

int ThreadPoolAIOScheduler::submit_pwrite(int                     fd,
                                          void*                   buf,
                                          size_t                  len,
                                          off_t                   offset,
                                          void*                   data,
                                          scheduler_callback_type callback)
{
    auto task = [this, fd, buf, len, offset, data, callback]() {
        ssize_t ret = pwrite(fd, buf, len, offset);
        callback(data, ret);


        std::unique_lock<std::mutex> lock(
            this->m_cv_lock); // we use a lock here to avoid TOCTOU bugs

        this->m_running_queries--;
        this->m_cv_submission.notify_all();
    };

    m_running_queries++;
    get_shared_io_pool().enqueue(task);


    return 1;
}

Scheduler* ThreadPoolAIOScheduler::duplicate() const
{
    return make_thread_pool_aio_scheduler();
}

} // namespace abstractio
} // namespace sse
