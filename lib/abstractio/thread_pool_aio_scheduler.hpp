#pragma once

#include "abstractio/scheduler.hpp"

#include <atomic>
#include <condition_variable>


namespace sse {
namespace abstractio {


class ThreadPoolAIOScheduler : public Scheduler
{
public:
    ThreadPoolAIOScheduler();
    ~ThreadPoolAIOScheduler();

    void wait_completions() override;

    int submit_pread(int                     fd,
                     void*                   buf,
                     size_t                  len,
                     off_t                   offset,
                     void*                   data,
                     scheduler_callback_type callback) override;


    int submit_pwrite(int                     fd,
                      void*                   buf,
                      size_t                  len,
                      off_t                   offset,
                      void*                   data,
                      scheduler_callback_type callback) override;

    // std::future<ReadBuffer> async_read(int    fd,
    //                                    size_t len,
    //                                    off_t  offset) override;

    // std::future<int> async_write(int    fd,
    //                              void*  buf,
    //                              size_t len,
    //                              off_t  offset) override;


private:
    std::atomic<uint64_t> m_submitted_queries_count{0};
    std::atomic<uint64_t> m_completed_queries_count{0};

    std::mutex              m_cv_lock;
    std::condition_variable m_cv_submission;
    // bool                    m_waiting_submissions{false};

    // #ifdef LOG_AIO_SCHEDULER_STATS
    //     std::atomic_size_t m_submit_calls{0};
    //     std::atomic_size_t m_submit_EAGAIN{0};
    //     std::atomic_size_t m_submit_partial{0};
    // #endif
};

} // namespace abstractio
} // namespace sse