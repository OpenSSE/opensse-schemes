#include "thread_pool_aio_scheduler.hpp"

#include "utils/thread_pool.hpp"

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
    while (true) {
        std::unique_lock<std::mutex> lock(m_cv_lock);
        m_cv_submission.wait(lock, [this] {
            return this->m_submitted_queries_count
                   >= this->m_completed_queries_count;
        });

        if (this->m_submitted_queries_count
            >= this->m_completed_queries_count) {
            break;
        }
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
        callback(data, ret);

        this->m_completed_queries_count++;
        this->m_cv_submission.notify_one();
    };

    m_submitted_queries_count++;
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

        this->m_completed_queries_count++;
        this->m_cv_submission.notify_one();
    };

    m_submitted_queries_count++;
    get_shared_io_pool().enqueue(task);


    return 1;
}

} // namespace abstractio
} // namespace sse
