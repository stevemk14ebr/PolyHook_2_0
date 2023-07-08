//
// Created by steve on 4/2/17.
//

#pragma once

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Misc.hpp"


/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

class Detour : public PLH::IHook {
public:
    Detour(
        const uint64_t fnAddress,
        const uint64_t fnCallback,
        uint64_t* userTrampVar,
        Mode mode
    ) : m_fnAddress(fnAddress),
        m_fnCallback(fnCallback),
        m_userTrampVar(userTrampVar),
        m_disasm(ZydisDisassembler(mode)) {
        assert(fnAddress != 0 && "Function address cannot be null");
        assert(fnCallback != 0 && "Callback address cannot be null");
        assert(sizeof(*userTrampVar) == sizeof(uint64_t) && "Given trampoline holder is too small");
    }

    virtual ~Detour() {
        if (m_hooked) {
            unHook();
        }
    }

    virtual bool unHook() override;

    /**
    This is for restoring hook bytes if a 3rd party uninstalled them.
    DO NOT call this after unHook(). This may only be called after hook()
    but before unHook()
    **/
    bool reHook() override;

    HookType getType() const override {
        return HookType::Detour;
    }

    virtual Mode getArchType() const = 0;

    uint8_t getMaxDepth() const;

    void setMaxDepth(uint8_t maxDepth);

    void setIsFollowCallOnFnAddress(bool value);

protected:
    uint64_t m_fnAddress;
    uint64_t m_fnCallback;
    uint64_t* m_userTrampVar;
    ZydisDisassembler m_disasm;
    uint8_t m_maxDepth = 5;
    uint64_t m_trampoline = 0;
    uint16_t m_trampolineSz = 0;
    insts_t m_originalInsts;

    /*Save the instructions used for the hook so that we can re-write in rehook()
    Note: There's a nop range we store too so that it doesn't need to be re-calculated
    */
    insts_t m_hookInsts;
    uint16_t m_nopProlOffset = 0;
    uint16_t m_nopSize = 0;
    uint32_t m_hookSize = 0;
    bool m_isFollowCallOnFnAddress = true;  // whether follow 'CALL' destination

    /**Walks the given vector of instructions and sets roundedSz to the lowest size possible that doesn't split any instructions and is greater than minSz.
    If end of function is encountered before this condition an empty optional is returned. Returns instructions in the range start to adjusted end**/
    static std::optional<insts_t> calcNearestSz(const insts_t& functionInsts, uint64_t minSz, uint64_t& roundedSz);

    /**If function starts with a jump follow it until the first non-jump instruction, recursively. This handles already hooked functions
    and also compilers that emit jump tables on function call. Returns true if resolution was successful (nothing to resolve, or resolution worked),
    false if resolution failed.**/
    bool followJmp(insts_t& functionInsts, uint8_t curDepth = 0);

    /**Expand the prologue up to the address of the last jmp that points back into the prologue. This
    is necessary because we modify the location of things in the prologue, so re-entrant jmps point
    to the wrong place. Therefore we move all of it to the trampoline where there is ample space to
    relocate and create jmp tbl entries**/
    bool expandProlSelfJmps(insts_t& prol,
        const insts_t& func,
        uint64_t& minProlSz,
        uint64_t& roundProlSz
    );

    /**
     * Insert nops from [Base, Base+size).
     * Generates as many nop instructions as necessary to fill the give size.
     * This function ensures that generated nops won't be reused as a code cave by Polyhook.
     * Hence, it will never emit more than 8 0x90 single byte nops in a row.
     */
    insts_t make_nops(uint64_t address, uint16_t size) const;

    static void buildRelocationList(
        insts_t& prologue,
        uint64_t roundProlSz,
        int64_t delta,
        insts_t& instsNeedingEntry,
        insts_t& instsNeedingReloc,
        insts_t& instsNeedingTranslation
    );

    /**
     * Corrects displacement for IP-relative instructions
     * @return Jump table entries
     */
    template<typename MakeJmpFn>
    insts_t relocateTrampoline(
        insts_t& prologue,
        uint64_t jmpTblStart,
        const int64_t delta,
        MakeJmpFn makeJmp,
        const insts_t& instsNeedingReloc,
        const insts_t& instsNeedingEntry
    ) {
        uint64_t jmpTblCurAddr = jmpTblStart;
        insts_t jmpTblEntries;

        // MIGHT NEED TO REDO ALL THIS JUMP TABLE STUFF IT's CONFUSING - needlessly
        for (auto& inst: prologue) {

            if (std::find(instsNeedingEntry.begin(), instsNeedingEntry.end(), inst) != instsNeedingEntry.end()) {
                assert(inst.hasDisplacement());
                // make an entry pointing to where inst did point to
                auto entry = makeJmp(jmpTblCurAddr, inst);

                // Move to next entry, some jmp types can emit more than one instruction
                jmpTblCurAddr += calcInstsSz(entry);

                ZydisDisassembler::writeEncoding(entry, *this);
                jmpTblEntries.insert(jmpTblEntries.end(), entry.begin(), entry.end());
            } else if (std::find(instsNeedingReloc.begin(), instsNeedingReloc.end(), inst) != instsNeedingReloc.end()) {
                assert(inst.hasDisplacement());

                const uint64_t instsOldDest = inst.getDestination();
                inst.setAddress(inst.getAddress() + delta);
                inst.setDestination(instsOldDest);
            } else {
                inst.setAddress(inst.getAddress() + delta);
            }

            ZydisDisassembler::writeEncoding(inst, *this);
        }
        return jmpTblEntries;
    }
};

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
*                              |    jump_holder1       | -> points into Trampoline.prologue
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
