#include "abstractio/linux_aio_scheduler.hpp"

namespace sse {
namespace abstractio {
Scheduler* make_linux_aio_scheduler(const size_t   page_size,
                                    const unsigned n_events)
{
    return new LinuxAIOScheduler(page_size, n_events);
}
} // namespace abstractio
} // namespace sse
