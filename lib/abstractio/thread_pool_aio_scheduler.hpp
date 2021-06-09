#pragma once

#include "abstractio/scheduler.hpp"

#include <atomic>
#include <condition_variable>


namespace sse {
namespace abstractio {


class ThreadPoolAIOScheduler : public Scheduler
{
public:
    ThreadPoolAIOScheduler() = default;
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

    Scheduler* duplicate() const override;

private:
    // std::atomic<uint64_t> m_submitted_queries_count{0};
    // std::atomic<uint64_t> m_completed_queries_count{0};
    std::atomic<uint64_t> m_running_queries{0};

    std::mutex              m_cv_lock;
    std::condition_variable m_cv_submission;
};

} // namespace abstractio
} // namespace sse