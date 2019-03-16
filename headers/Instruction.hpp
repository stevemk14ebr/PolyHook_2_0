//
// Created by steve on 3/25/17.
//

#ifndef POLYHOOK_2_0_INSTRUCTION_HPP
#define POLYHOOK_2_0_INSTRUCTION_HPP

#include <cassert>
#include <string>
#include <vector>
#include <sstream>
#include <iostream> //ostream operator
#include <iomanip> //setw
#include <type_traits>

#include "headers/UID.hpp"
#include "headers/Enums.hpp"

#ifdef _WIN32
#define DEBUG_BREAK __debugbreak()
#else
#include <signal.h>
#define DEBUG_BREAK raise(SIGTRAP);
#endif

namespace PLH {
class Instruction {
public:
	union Displacement {
		int64_t  Relative = 0;
		uint64_t Absolute;
	};

	Instruction(uint64_t address,
				const Displacement& displacement,
				const uint8_t displacementOffset,
				const bool isRelative,
				const std::vector<uint8_t>& bytes,
				const std::string& mnemonic,
				const std::string& opStr);

	Instruction(uint64_t address,
				const Displacement& displacement,
				const uint8_t displacementOffset,
				bool isRelative,
				uint8_t bytes[],
				size_t arrLen,
				const std::string& mnemonic,
				const std::string& opStr);
	
	/**Get the address of where the instruction points if it's a branching instruction
	* @Notes: Handles eip/rip & immediate branches correctly
	* **/
	uint64_t getDestination() const;

	void setDestination(const uint64_t dest);

	/**Get the address of the instruction in memory**/
	uint64_t getAddress() const;

	/**Set a new address of the instruction in memory
	@Notes: Doesn't move the instruction, marks it for move on writeEncoding and relocates if appropriate**/
	void setAddress(const uint64_t address);

	/**Get the displacement from current address**/
	Displacement getDisplacement() const;

	/**Set where in the instruction bytes the offset is encoded**/
	void setDisplacementOffset(const uint8_t offset);

	void setBranching(const bool status);

	/**Get the offset into the instruction bytes where displacement is encoded**/
	uint8_t getDisplacementOffset() const;

	/**Check if displacement is relative to eip/rip**/
	bool isDisplacementRelative() const;

	/**Check if the instruction is a type with valid displacement**/
	bool hasDisplacement() const;

	bool isBranching() const;

	const std::vector<uint8_t>& getBytes() const;

	/**Get short symbol name of instruction**/
	std::string getMnemonic() const;

	/**Get symbol name and parameters**/
	std::string getFullName() const;

	size_t getDispSize();

	size_t size() const;

	void setRelativeDisplacement(const int64_t displacement);

	void setAbsoluteDisplacement(const uint64_t displacement);

	long getUID() const;

	template<typename T>
	static T calculateRelativeDisplacement(uint64_t from, uint64_t to, uint8_t insSize) {
		if (to < from)
			return (T)(0 - (from - to) - insSize);
		return (T)(to - (from + insSize));
	}
private:
	uint64_t     m_address;       //Address the instruction is at
	Displacement m_displacement;  //Where an instruction points too (valid for jmp + call types)
	uint8_t      m_dispOffset;    //Offset into the byte array where displacement is encoded
	bool         m_isRelative;    //Does the displacement need to be added to the address to retrieve where it points too?
	bool         m_hasDisplacement; //Does this instruction have the displacement fields filled (only rip/eip relative types are filled)
	bool		 m_isBranching; //Does this instrunction jmp/call or otherwise change control flow

	std::vector<uint8_t> m_bytes; //All the raw bytes of this instruction
	std::string          m_mnemonic; //If you don't know what these two are then gtfo of this source code :)
	std::string          m_opStr;
	UID m_uid;
};

	typedef std::vector<Instruction> insts_t;
	bool operator==(const Instruction& lhs, const Instruction& rhs);
	uint16_t calcInstsSz(const insts_t& insts);
template<typename T>
std::string instsToStr(const T& container) {
	std::stringstream ss;
	ss << container;
	return ss.str();
}

	std::ostream& operator<<(std::ostream& os, const insts_t& v);
	std::ostream& operator<<(std::ostream& os, const Instruction& obj);



/**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
 * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
PLH::insts_t makex64PreferredJump(const uint64_t address, const uint64_t destination);

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::insts_t makex64MinimumJump(const uint64_t address, const uint64_t destination, const uint64_t destHolder);
PLH::insts_t makex86Jmp(const uint64_t address, const uint64_t destination);
PLH::insts_t makex64PreferredJump(const uint64_t address, const uint64_t destination);
PLH::insts_t makeAgnosticJmp(const uint64_t address, const uint64_t destination);
}
#endif //POLYHOOK_2_0_INSTRUCTION_HPP
