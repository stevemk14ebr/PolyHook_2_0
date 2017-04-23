//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MISC_HPP
#define POLYHOOK_2_0_MISC_HPP
#include <stdexcept>
#include <cassert>
namespace PLH
{
    enum class Platform
    {
        WIN,
        UNIX
    };

    class NotImplementedException : public std::logic_error
    {
    public:
        NotImplementedException() : std::logic_error("Function not implemented")
        {

        }
    };

    //http://stackoverflow.com/questions/4840410/how-to-align-a-pointer-in-c
    static inline uint8_t* AlignUpwards(uint8_t *stack, uintptr_t align)
    {
        assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
        assert(stack != 0);

        uintptr_t addr  = (uintptr_t)stack;
        if (addr % align != 0)
            addr += align - addr % align;
        assert(addr >= (uintptr_t)stack);
        return (uint8_t *)addr;
    }

    static inline uint8_t* AlignDownwards(uint8_t *stack, uintptr_t align)
    {
        assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
        assert(stack != 0);

        uintptr_t addr  = (uintptr_t)stack;
        addr -= addr % align;
        assert(addr <= (uintptr_t)stack);
        return (uint8_t *)addr;
    }
}
#endif //POLYHOOK_2_0_MISC_HPP
