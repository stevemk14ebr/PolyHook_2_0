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

    class ValueNotSetException : public std::logic_error
    {
    public:
        ValueNotSetException() : std::logic_error("Value not set in optional object")
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

    //TO-DO: replace with c++17 optional when appropriately supported
    template<typename T>
    class Optional
    {
    public:
        Optional(const T& val)
        {
            m_HasVal = true;
            m_Val = val;
        }

        Optional()
        {
            m_HasVal = false;
        }

        T get() const
        {
            if(m_HasVal)
                return m_Val;
            throw ValueNotSetException();
        }

        operator bool()
        {
            return m_HasVal;
        }
    private:
        bool m_HasVal;
        T m_Val;
    };

}
#endif //POLYHOOK_2_0_MISC_HPP
