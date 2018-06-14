//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include <optional>
#include <cassert>
#include <map>

#include "headers/ADisassembler.hpp"
#include "headers/IHook.hpp"
#include "headers/Enums.hpp"
#include "headers/ErrorLog.hpp"
#include <optional>

/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

class Trampoline {
public:
	template<typename T>
	T get() {
		assert(m_trampoline);
		return (T)*m_trampoline;
	}
private:
	std::optional<uint64_t> m_trampoline;
};

class Detour : public PLH::IHook
{
public:
	Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != 0 && fnCallback != 0);
		m_fnAddress = fnAddress;
		m_fnCallback = fnCallback;
		m_hooked = false;
	}

	Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != nullptr && fnCallback != nullptr);
		m_fnAddress = (uint64_t)fnAddress;
		m_fnCallback = (uint64_t)fnCallback;
		m_hooked = false;
	}

	virtual HookType getType() const {
		return HookType::Detour;
	}

	virtual Trampoline& getTrampoline() {
		return m_trampolines.at(m_fnAddress);
	}

	virtual Mode getArchType() const = 0;
protected:
    uint64_t                m_fnAddress;
    uint64_t                m_fnCallback;
	ADisassembler&			m_disasm;

	/**Walks the given vector of instructions and sets roundedSz to the lowest size possible that doesn't split any instructions and is greater than minSz.
	If end of function is encountered before this condition an empty optional is returned. Returns instructions in the range start to adjusted end**/
	std::optional<insts_t> calcNearestSz(const insts_t& functionInsts, const uint64_t minSz,
			uint64_t& roundedSz);

	/**If function starts with a jump follow it until the first non-jump character recursively. This handles already hooked functions
	and also compilers that emit jump tables on function call. Returns true if resolution was successful (nothing to resolve, or resolution worked),
	false if resolution failed.**/
	bool followProlJmp(insts_t& functionInsts, const uint8_t curDepth = 0, const uint8_t depth = 3);

	/**Expand prologue to make room for jump table if instrs point back into it. The expansion will overwrite more instructions, which could
	require yet another jump table entry, so be careful to account for that**/
	std::optional<insts_t> expandProl(const insts_t& prolInsts, const insts_t& funcInsts, uint64_t& minSz, uint64_t& roundedSz, const uint8_t jmpSz, bool& expanded);

	/**Build the jmp table needed for when insts point back into the prologue. Also repoint the insts to the jmp entries
	instead of whereever they went into the prologue**/
	template<typename MakeJmpFn>
	void buildProlJmpTbl(const insts_t& prol, insts_t& jmpTbl, insts_t& jmpToFix,
		const uint64_t trampolineAddr,
		const uint8_t jmpSz,
		MakeJmpFn makeJmp);

	bool isSrcBranchNotRelocated(const insts_t& sources, const uint64_t relocAddrEnd);

	// fnAddress -> Trampoline map, allows trampoline references to be handed out and later filled by hook(). Global lifetime
	static std::map<uint64_t, Trampoline> m_trampolines;
    bool                    m_hooked;
};

template<typename MakeJmpFn>
void PLH::Detour::buildProlJmpTbl(const insts_t& prol, insts_t& jmpTbl,
	insts_t& jmpToFix,
	const uint64_t trampolineAddr,
	const uint8_t jmpSz,
	MakeJmpFn makeJmp)
{
	PLH::branch_map_t branchMap = m_disasm.getBranchMap();

	const uint64_t prolStart = prol.at(0).getAddress();
	const uint64_t tblStart = prolStart + jmpSz;
	int tblIdx = 0;
	for (int i = 0; i < prol.size(); i++)
	{
		auto inst = prol.at(i);
		if (branchMap.find(inst.getAddress()) == branchMap.end())
			continue;

		// the (long) jmp that goes from prologue to trampoline
		const uint64_t entryAddr = tblStart + tblIdx * jmpSz;


		// point all jmp sources to the tbl entry instead of the to-be-moved instruction
		bool needEntry = false;
		insts_t branchSources = branchMap.at(inst.getAddress());
		for (auto& branch : branchSources) {
			if (branch.getAddress() > prolStart + prol.size()) {
				branch.setDestination(entryAddr);
				jmpToFix.push_back(branch);
				needEntry = true;
			}
		}

		if (!needEntry)
			continue;

		auto jmpEntry = makeJmp(entryAddr, trampolineAddr + (inst.getAddress() - prolStart));
		jmpTbl.insert(jmpTbl.end(), jmpEntry.begin(), jmpEntry.end());
		tblIdx++;
	}
}

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
#endif //POLYHOOK_2_0_ADETOUR_HPP
