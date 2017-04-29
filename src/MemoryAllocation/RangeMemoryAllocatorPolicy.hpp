//
// Created by steve on 4/25/17.
//

#ifndef POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#define POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#include <memory>
#include <type_traits>
#include "ARangeMemAllocator.hpp"

#define ALLOCATOR_TRAITS(T)                \
typedef T                 type;            \
typedef type              value_type;      \
typedef value_type*       pointer;         \
typedef value_type const* const_pointer;   \
typedef value_type&       reference;       \
typedef value_type const& const_reference; \
typedef std::size_t       size_type;       \
typedef std::ptrdiff_t    difference_type; \

//http://jrruethe.github.io/blog/2015/11/22/allocators/
namespace PLH
{
    template<class T>
    class RangeMemoryAllocatorPolicy
    {
    public:
        ALLOCATOR_TRAITS(T)

        RangeMemoryAllocatorPolicy(uint64_t Min, uint64_t Max, PLH::ARangeMemAllocator& AllocImp) : std::allocator_traits<T>()
        {
            m_Min = Min;
            m_Max = Max;
            m_AllocImp = AllocImp;
        }

        pointer allocate(size_type count, const_pointer = 0)
        {
            std::size_t AllocationSize = count*sizeof(value_type);
            std::size_t NeededAlignment = std::alignment_of<value_type>::value;
            std::vector<PLH::AllocatedMemoryBlock> CandidateRegions = m_AllocImp.GetAllocatedCaves();
            for(const auto& Region : CandidateRegions)
            {

            }
        }

        void deallocate(pointer ptr, size_type n)
        {

        }

        ~RangeMemoryAllocatorPolicy()
        {

        }
    private:
        uint64_t m_Min;
        uint64_t m_Max;
        PLH::ARangeMemAllocator m_AllocImp;
    };
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
