#include "abstractio/linux_aio_scheduler.hpp"
#include "abstractio/thread_pool_aio_scheduler.hpp"
#include "configure.hpp"
#include "utils/utils.hpp"

namespace sse {
namespace abstractio {

size_t Scheduler::async_io_page_size(int fd)
{
    return std::max(utility::os_page_size(), utility::device_page_size(fd));
}

#ifdef HAS_LIBAIO
Scheduler* make_linux_aio_scheduler(const size_t   page_size,
                                    const unsigned n_events)
{
    return new LinuxAIOScheduler(page_size, n_events);
}
#endif

Scheduler* make_thread_pool_aio_scheduler()
{
    return new ThreadPoolAIOScheduler();
}


Scheduler* make_default_aio_scheduler(const size_t page_size)
{
#ifdef HAS_LIBAIO
    constexpr size_t kDefaultNEvents = 128;
    return make_linux_aio_scheduler(page_size, kDefaultNEvents);
#else
    (void)page_size;
    return make_thread_pool_aio_scheduler();
#endif
}


} // namespace abstractio
} // namespace sse
