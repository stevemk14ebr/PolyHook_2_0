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

#pragma warning(disable:4100)
#pragma warning(disable:4189)

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

	virtual uint64_t getTrampoline() const {
		assert(m_hooked);
		if (!m_hooked) 
			throw "Must hook before getting trampoline";
		
		return m_trampoline;
	}

	virtual Mode getArchType() const = 0;
protected:
    uint64_t                m_fnAddress;
    uint64_t                m_fnCallback;
	uint64_t				m_trampoline;
	ADisassembler&			m_disasm;

	/**Walks the given vector of instructions and sets roundedSz to the lowest size possible that doesn't split any instructions and is greater than minSz.
	If end of function is encountered before this condition an empty optional is returned. Returns instructions in the range start to adjusted end**/
	std::optional<insts_t> calcNearestSz(const insts_t& functionInsts, const uint64_t minSz,
			uint64_t& roundedSz);

	/**If function starts with a jump follow it until the first non-jump character recursively. This handles already hooked functions
	and also compilers that emit jump tables on function call. Returns true if resolution was successful (nothing to resolve, or resolution worked),
	false if resolution failed.**/
	bool followJmp(insts_t& functionInsts, const uint8_t curDepth = 0, const uint8_t depth = 3);

	/**Build the jmp table needed for when insts point back into the prologue. Returns the instructions that make the jump table, modifies the input prol to
	the expanded size needed to insert the jump table**/
	template<typename MakeJmpFn>
	bool buildProlJmpTbl(insts_t& prol, const insts_t& func,
		insts_t& writeLater,
		const uint64_t trampAddr,
		uint64_t& minProlSz,
		uint64_t& roundProlSz,
		const uint64_t jmpSz,
		MakeJmpFn makeJmp, insts_t& tbl);

	template<typename MakeJmpFn>
	std::optional<insts_t> makeTrampoline(insts_t& prologue, const uint64_t trampStart, const uint64_t roundProlSz, const uint8_t jmpSz,  MakeJmpFn makeJmp);

    bool                    m_hooked;
};

template<typename MakeJmpFn>
bool PLH::Detour::buildProlJmpTbl(insts_t& prol, const insts_t& func,
	insts_t& writeLater,
	const uint64_t trampAddr,
	uint64_t& minProlSz,
	uint64_t& roundProlSz,
	const uint64_t jmpSz, 
	MakeJmpFn makeJmp,
	insts_t& tbl)
{
	insts_t jmpsToFix;
	const uint64_t prolStart = prol.front().getAddress();
	branch_map_t branchMap = m_disasm.getBranchMap();

	/* expand round, check for jmps into prol and expand prologue
	to make room for jmp tbl entries. Take care if a jmp src overlaps
	the prologue or the to-be expanded prologue*/
	for (size_t i = 0; i < prol.size(); i++)
	{
		auto inst = prol.at(i);

		// is there a jump pointing at the current instruction?
		if (branchMap.find(inst.getAddress()) == branchMap.end())
			continue;

		insts_t srcs = branchMap.at(inst.getAddress());

		uint8_t stepSz = 0;
		bool needExp = false;
		bool canJustStep = true;
		for (const auto& src : srcs) {
			/* just include the jmp if it's the only src and it's in the prol/exp. prol.*/
			if (src.getAddress() > prol.back().getAddress() + prol.back().size()) {
				canJustStep = false;
			}

			stepSz = (uint8_t)src.size();

			/* we could have srcs already within the prologue, expand if any src is outside*/
			if (src.getAddress() > prol.back().getAddress())
				needExp = true;
		}

		/* if a src is about to eclipse the expansion, then it can be 
		   just stepped over, and will be relocated later by the trampoline
		   table, and doesn't need an entry in the prol tbl
		*/
		if (canJustStep && needExp) {
			assert(stepSz > 0 && stepSz < 12);
			minProlSz += stepSz;
		} else if (needExp){
			minProlSz += jmpSz;
		}

		// expand prol by one entry size, may fail if prol to small
		auto prolOpt = calcNearestSz(func, minProlSz, roundProlSz);
		if (!prolOpt)
			return false;
		prol = *prolOpt;
	}

	/* count srcs that are outside of prologue area. Must happen
	after the expansion as the end of prol is variable*/
	for (size_t i = 0; i < prol.size(); i++) {
		auto inst = prol.at(i);

		// is there a jump pointing at the current instruction?
		if (branchMap.find(inst.getAddress()) == branchMap.end())
			continue;

		insts_t srcs = branchMap.at(inst.getAddress());
		for (auto& src : srcs) {
			if (src.getAddress() > prol.back().getAddress()) {
				jmpsToFix.push_back(src);
			}
		}
	}

	/* build the tbl entries and fix the srcs to point to them */
	uint8_t tblIdx = 0;
	const uint64_t tblStart = prolStart + minProlSz;
	for (auto& fix : jmpsToFix) {
		const uint64_t tblAddr = tblStart + tblIdx * jmpSz;
		const uint64_t jmpDest = fix.getDestination() - prolStart + trampAddr;
		
		insts_t entry = makeJmp(tblAddr, jmpDest);
		fix.setDestination(tblAddr);
		tbl.insert(tbl.end(), entry.begin(), entry.end());
		tblIdx++;
	}
	writeLater = jmpsToFix;

	return true;
}

template<typename MakeJmpFn>
std::optional<PLH::insts_t> PLH::Detour::makeTrampoline(insts_t& prologue, const uint64_t trampStart, const uint64_t roundProlSz, const uint8_t jmpSz, MakeJmpFn makeJmp)
{
	const uint64_t delta = std::llabs(prologue.front().getAddress() - trampStart);
	uint64_t trampAddr = trampStart;
	const uint64_t jmpToProlAddr = trampStart + roundProlSz;
	uint64_t jmpTblAddr = jmpToProlAddr + jmpSz; // end of copied prol + space for jmp back to prol is start of tramp jump table
	
	assert(prologue.size() > 0);
	assert(jmpTblAddr > trampAddr);

	auto jmpToProl = makeJmp(jmpToProlAddr, prologue.front().getAddress() + roundProlSz);
	m_disasm.writeEncoding(jmpToProl);

	// just a convenience list to see what the jmp table became
	PLH::insts_t jmpTblEntries;

	for (auto& inst : prologue) {
		uint64_t instDest = inst.getDestination();
		inst.setAddress(trampAddr);

		// relocate if it doesn't point inside trampoline prol
		if (inst.hasDisplacement() &&
			(inst.getDestination() < trampStart ||
				inst.getDestination() > trampStart + roundProlSz)) {

			// can inst just be re-encoded or do we need a tbl entry
			const uint8_t dispSzBits = (uint8_t)inst.getDispSize() * 8;
			const uint64_t maxInstDisp = (uint64_t)(std::pow(2, dispSzBits) / 2.0 - 1.0); // 2^bitSz give max val, /2 and -1 because signed
			if (delta > maxInstDisp) {
				// make an entry pointing to where inst did point to
				auto entry = makeJmp(jmpTblAddr, instDest); 

				// point instruction to entry
				inst.setDestination(jmpTblAddr);
				jmpTblAddr += jmpSz;

				m_disasm.writeEncoding(entry);
				jmpTblEntries.insert(jmpTblEntries.end(), entry.begin(), entry.end());
			} else {
				inst.setDestination(instDest);
			}
		}

		trampAddr += inst.size();
		m_disasm.writeEncoding(inst);
	}

	assert(trampAddr > trampStart);
	if (jmpTblEntries.size() > 0)
		return jmpTblEntries;
	else
		return std::nullopt;
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
#endif //POLYHOOK_2_0_ADETOUR_HPP
