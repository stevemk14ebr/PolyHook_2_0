//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include "headers/CapstoneDisassembler.hpp"
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Detour/x86DetourImp.hpp"
#include "headers/Enums.hpp"

#include <map>
#include <sstream>
/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

class Detour : public PLH::IHook
{
public:
    Detour(const uint64_t fnAddress, const uint64_t fnCallback);

    Detour(const char* fnAddress, const char* fnCallback);

    virtual bool hook() override;

    virtual bool unHook() override;

    virtual PLH::HookType getType() override;

    template<typename T>
    T getOriginal() {
        assert(m_trampoline.isOk());
        return (T)m_trampoline.unwrap().data();
    }

private:
    uint64_t               m_fnAddress;
    uint64_t               m_fnCallback;
    bool                   m_hooked;
};

Detour::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) {
    assert(hookAddress != 0 && callbackAddress != 0);
    m_fnAddress  = hookAddress;
    m_fnCallback = callbackAddress;
    m_hooked     = false;
}

Detour::Detour(const char* hookAddress, const char* callbackAddress) {
    assert(hookAddress != nullptr && callbackAddress != nullptr);
    m_fnAddress  = (uint64_t)hookAddress;
    m_fnCallback = (uint64_t)callbackAddress;
    m_hooked     = false;
}

bool Detour::hook() {

    /** Before Hook:                                                After hook:
     *
     * --------fnAddress--------                                    --------fnAddress--------
     * |    prologue           |                                   |    jmp fnCallback      | <- this may be an indirect jmp
     * |    ...body...         |      ----> Converted into ---->   |    ...jump table...    | if it is, it reads the final
     * |                       |                                   |    ...body...          |  dest from end of trampoline (optional indirect loc)
     * |    ret                |                                   |    ret                 |
     * -------------------------                                   --------------------------
     *                                                                           ^ jump table may not exist.
     *                                                                           If it does, and it uses indirect style
     *                                                                           jumps then prologueJumpTable exists.
     *                                                                           prologueJumpTable holds pointers
     *                                                                           to where the indirect jump actually
     *                                                                           lands.
     *
     *                               Created during hooking:
     *                              --------Trampoline--------
     *                              |     prologue            | Executes fnAddress's prologue (we overwrote it with jmp)
     *                              |     jmp fnAddress.body  | Jmp back to first address after the overwritten prologue
     *                              |  ...jump table...       | Long jmp table that short jmps in prologue point to
     *                              |  optional indirect loc  | may or may not exist depending on jmp type we used
     *                              --------------------------
     *
     *                              Conditionally exists:
     *                              ----prologueJumpTable-----
     *                              |    jump_holder1       | -> points into Trampolinee.prologue
     *                              |    jump_holder2       | -> points into Trampoline.prologue
     *                              |       ...             |
     *                              ------------------------
     *
     *
     *                      Example jmp table (with an example prologue, this prologue lives in trampoline):
     *
     *        Prologue before fix:          Prologue after fix:
     *        ------prologue-----           ------prologue----          ----jmp table----
     *        push ebp                      push ebp                    jump_table.Entry1: long jmp original je address + 0x20
     *        mov ebp, esp                  mov ebp, esp
     *        cmp eax, 1                    cmp eax, 1
     *        je 0x20                       je jump_table.Entry1
     *
     *        This jump table is needed because the original je instruction's displacement has a max vale of 0x80. It's
     *        extremely likely that our Trampoline was not placed +-0x80 bytes away from fnAddress. Therefore we have
     *        to add an intermediate long jmp so that the moved je will still jump to where it originally pointed. To
     *        do this we insert a jump table at the end of the trampoline, there's N entrys where conditional jmp N points
     *        to jump_table.EntryN.
     *
     *
     *                          User Implements callback as C++ code
     *                              --------fnCallback--------
     *                              | ...user defined code... |
     *                              |   return Trampoline     |
     *                              |                         |
     *                              --------------------------
     * **/
}

bool Detour::unHook() {

}
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
