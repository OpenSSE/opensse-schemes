#pragma once

#include <sse/schemes/tethys/details/tethys_graph.hpp>

namespace sse {
namespace tethys {


enum TethysAssignmentEdgeOrientation : uint8_t
{
    IncomingEdge = 0,
    OutgoingEdge
};

struct TethysAssignmentInfo
{
    size_t                          list_length;
    size_t                          assigned_list_length;
    size_t                          dual_assigned_list_length;
    TethysAssignmentEdgeOrientation edge_orientation;

    TethysAssignmentInfo(const details::Edge&            e,
                         TethysAssignmentEdgeOrientation o)
        : list_length(e.capacity), edge_orientation(o)
    {
        if (edge_orientation == OutgoingEdge) {
            assigned_list_length      = e.flow;
            dual_assigned_list_length = e.rec_flow;
        } else {
            assigned_list_length      = e.rec_flow;
            dual_assigned_list_length = e.flow;
        }
    }
};

template<class T>
struct TethysStashSerializationValue
{
    const std::vector<T>* data;
    TethysAssignmentInfo  assignement_info;

    TethysStashSerializationValue(const std::vector<T>* d,
                                  TethysAssignmentInfo  ai)
        : data(d), assignement_info(ai)
    {
    }
};

} // namespace tethys
} // namespace sse