//
// Created by steve on 5/20/17.
//

#ifndef POLYHOOK_2_0_RANGEMEMORYSTLALLOCATOR_H
#define POLYHOOK_2_0_RANGEMEMORYSTLALLOCATOR_H
#include "src/MemoryAllocation/RangeMemoryAllocatorPolicy.hpp"
#include "src/MemoryAllocation/RangeMemoryAllocatorObjectTraits.hpp"

namespace PLH {
    template<typename T, typename Platform,
            typename Policy = PLH::RangeMemoryAllocatorPolicy<T, Platform>,
            typename Traits = PLH::ObjectTraits<T> >
    class Allocator : public Policy, public Traits {
    private :
        typedef Policy AllocationPolicy;
        typedef Traits TTraits;

    public:
        typedef typename AllocationPolicy::size_type size_type;
        typedef typename AllocationPolicy::difference_type difference_type;
        typedef typename AllocationPolicy::pointer pointer;
        typedef typename AllocationPolicy::const_pointer const_pointer;
        typedef typename AllocationPolicy::reference reference;
        typedef typename AllocationPolicy::const_reference const_reference;
        typedef typename AllocationPolicy::value_type value_type;

    public :
        template<typename U>
        struct rebind
        {
            typedef Allocator<U, Platform,
                    typename AllocationPolicy::template rebind<U>::other,
                    typename TTraits::template rebind<U>::other> other;
        };
    public :
        inline explicit Allocator(uint64_t Min, uint64_t Max) : Policy(Min,Max) {}
        inline ~Allocator() {}
        inline Allocator(Allocator const& rhs):Traits(rhs), Policy(rhs) {}
    };    //    end of class Allocator


    template<typename T,typename Platform, typename P, typename Tr>
    inline bool operator==(Allocator<T,Platform, P, Tr> const& lhs,
                           Allocator<T, Platform, P, Tr> const& rhs)
    {
        //Call policy ==
        return operator==(static_cast<P&>(lhs), static_cast<P&>(rhs));
    }

    template<typename T,typename Platform, typename P, typename Tr, typename OtherAllocator>
    inline bool operator==(Allocator<T, Platform, P, Tr> const& lhs,
                           OtherAllocator const& rhs) {
        return operator==(static_cast<P&>(lhs), rhs);
    }

    template<typename T,typename Platform, typename P, typename Tr>
    inline bool operator!=(Allocator<T, Platform, P, Tr> const& lhs,
                           Allocator<T, Platform, P, Tr> const& rhs) {
        return !operator==(lhs, rhs);
    }

    template<typename T,typename Platform, typename P, typename Tr,
            typename OtherAllocator>
    inline bool operator!=(Allocator<T, Platform, P, Tr> const& lhs,
                           OtherAllocator const& rhs) {
        return !operator==(lhs, rhs);
    }
}
#endif //POLYHOOK_2_0_RANGEMEMORYSTLALLOCATOR_H
