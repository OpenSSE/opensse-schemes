#include "abstractio/linux_aio_scheduler.hpp"
#include "utils/utils.hpp"

namespace sse {
namespace abstractio {
Scheduler* make_linux_aio_scheduler(const size_t   page_size,
                                    const unsigned n_events)
{
    return new LinuxAIOScheduler(page_size, n_events);
}

size_t Scheduler::async_io_page_size(int fd)
{
    return std::max(utility::os_page_size(), utility::device_page_size(fd));
}

} // namespace abstractio
} // namespace sse
