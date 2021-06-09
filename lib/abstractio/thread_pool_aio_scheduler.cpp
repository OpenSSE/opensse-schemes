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
    std::cerr << "Start destroying\n";

    ThreadPoolAIOScheduler::wait_completions();
    std::cerr << "Scheduler destroyed\n";
}

void ThreadPoolAIOScheduler::wait_completions()
{
    std::cerr << "Wait completions\n";

    while (true) {
        std::unique_lock<std::mutex> lock(m_cv_lock);
        m_cv_submission.wait(lock, [this] {
            return this->m_submitted_queries_count
                   <= this->m_completed_queries_count;
        });

        if (this->m_submitted_queries_count
            <= this->m_completed_queries_count) {
            break;
        }
    }
    std::cerr << "Finished Waiting for completions\n";
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
        } else if ((size_t)ret < len) {
            sse::logger::logger()->warn(
                "Incomplete pread: {} instead of {}", ret, len);
        }
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

Scheduler* ThreadPoolAIOScheduler::duplicate() const
{
    std::cerr << "Duplicate\n";

    return make_thread_pool_aio_scheduler();
}

} // namespace abstractio
} // namespace sse
