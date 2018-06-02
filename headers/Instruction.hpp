//
// Created by steve on 3/25/17.
//

#ifndef POLYHOOK_2_0_INSTRUCTION_HPP
#define POLYHOOK_2_0_INSTRUCTION_HPP

#include <string>
#include <vector>
#include <sstream>
#include <iostream> //ostream operator
#include <iomanip> //setw
#include <type_traits>

#include "headers/UID.hpp"
namespace PLH {
class Instruction
{
public:
    union Displacement
    {
        int64_t  Relative;
        uint64_t Absolute;
    };

    Instruction(uint64_t address,
                const Displacement& displacement,
                const uint8_t displacementOffset,
                const bool isRelative,
                const std::vector<uint8_t>& bytes,
                const std::string& mnemonic,
                const std::string& opStr) : m_uid(UID::singleton()) {

        Init(address, displacement, displacementOffset, isRelative, bytes, mnemonic, opStr);
    }

    Instruction(uint64_t address,
                const Displacement& displacement,
                const uint8_t displacementOffset,
                bool isRelative,
                uint8_t bytes[],
                size_t arrLen,
                const std::string& mnemonic,
                const std::string& opStr) : m_uid(UID::singleton()) {

        std::vector<uint8_t> Arr(bytes, bytes + arrLen);
        Init(address, displacement, displacementOffset, isRelative, Arr, mnemonic, opStr);
    }

	/**Get the address of where the instruction points if it's a branching instruction
	* @Notes: Handles eip/rip & immediate branches correctly
	* **/
    uint64_t getDestination() const {
        if (m_isRelative) {
            return m_address + m_displacement.Relative + size();
        }
        return m_displacement.Absolute;
    }

	/**Get the address of the instruction in memory**/
    uint64_t getAddress() const {
        return m_address;
    }

	/**Set a new address of the instruction in memory
	@Notes: Doesn't move the instruction, marks it for move on writeEncoding**/
    void setAddress(const uint64_t address) {
        m_address = address;
    }

	/**Get the displacement from current address**/
    Displacement getDisplacement() const {
        return m_displacement;
    }

	/**Set where in the instruction bytes the offset is encoded**/
    void setDisplacementOffset(const uint8_t offset) {
        m_dispOffset = offset;
    }

	/**Get the offset into the instruction bytes where displacement is encoded**/
    uint8_t getDisplacementOffset() const {
        return m_dispOffset;
    }

	/**Check if displacement is relative to eip/rip**/
    bool isDisplacementRelative() const {
        return m_isRelative;
    }

	/**Check if the instruction is a type with valid displacement**/
    bool hasDisplacement() const {
        return m_hasDisplacement;
    }

    const std::vector<uint8_t>& getBytes() const {
        return m_bytes;
    }

	/**Get short symbol name of instruction**/
    std::string getMnemonic() const {
        return m_mnemonic;
    }

	/**Get symbol name and parameters**/
    std::string getFullName() const {
        return m_mnemonic + " " + m_opStr;
    }

    size_t size() const {
        return m_bytes.size();
    }

    void setRelativeDisplacement(const int64_t displacement) {
        /**Update our class' book-keeping of this stuff and then modify the byte array.
         * This doesn't actually write the changes to the executeable code, it writes to our
         * copy of the bytes**/
        m_displacement.Relative = displacement;
        m_isRelative      = true;
        m_hasDisplacement = true;

        std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Relative, size() - getDisplacementOffset());
    }

    void setAbsoluteDisplacement(const uint64_t displacement) {
        m_displacement.Absolute = displacement;
        m_isRelative      = false;
        m_hasDisplacement = true;

        /**Update our class' book-keeping of this stuff and then modify the byte array.
         * This doesn't actually write the changes to the executeable code, it writes to our
         * copy of the bytes**/
        std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Absolute, size() - getDisplacementOffset());
    }

	long getUID() const {
		return m_uid.val;
	}
private:
    void Init(uint64_t address,
              const Displacement& displacement,
              const uint8_t displacementOffset,
              const bool isRelative,
              const std::vector<uint8_t>& bytes,
              const std::string& mnemonic,
              const std::string& opStr) {
        m_address         = address;
        m_displacement    = displacement;
        m_dispOffset      = displacementOffset;
        m_isRelative      = isRelative;
        m_bytes           = bytes;
        m_mnemonic        = mnemonic;
        m_opStr           = opStr;
        m_hasDisplacement = false;
    }

    uint64_t     m_address;       //Address the instruction is at
    Displacement m_displacement;  //Where an instruction points too (valid for jmp + call types)
    uint8_t      m_dispOffset;    //Offset into the byte array where displacement is encoded
    bool         m_isRelative;    //Does the displacement need to be added to the address to retrieve where it points too?
    bool         m_hasDisplacement; //Does this instruction have the displacement fields filled (only call + jmp types do)

    std::vector<uint8_t> m_bytes; //All the raw bytes of this instruction
    std::string          m_mnemonic; //If you don't know what these two are then gtfo of this source code :)
    std::string          m_opStr;

	UID m_uid;
};

inline bool operator==(const Instruction& lhs, const PLH::Instruction& rhs) {
	return lhs.getUID() == rhs.getUID();
}

inline std::ostream& operator<<(std::ostream& os, const PLH::Instruction& obj) {
    std::stringstream byteStream;
    for (std::size_t  i = 0; i < obj.size(); i++)
        byteStream << std::hex << std::setfill('0') << std::setw(2) << (unsigned)obj.getBytes()[i] << " ";

    os << std::hex << obj.getAddress() << " [" << obj.size() << "]: ";
    os << std::setfill(' ') << std::setw(30) << std::left << byteStream.str();
    os << obj.getFullName();

    if (obj.hasDisplacement() && obj.isDisplacementRelative())
        os << " -> " << obj.getDestination();
    os << std::dec;
    return os;
}

typedef std::vector<Instruction> insts_t;

template <typename T>
inline std::ostream& printInsts(std::ostream& out, const T& container)
{
	for (auto ii = container.cbegin(); ii != container.cend(); ++ii){
		out << *ii << std::endl;
	}
	return out;
}

inline std::ostream& operator<<(std::ostream& os, const std::vector<Instruction>& v) { return printInsts(os, v); }
//std::ostream& operator<<(std::ostream& os, const std::deque<X>& v) { return printInsts(os, v); }
//std::ostream& operator<<(std::ostream& os, const std::list<X>& v) { return printInsts(os, v); }
//std::ostream& operator<<(std::ostream& os, const std::set<X>& v) { return printInsts(os, v); }
//std::ostream& operator<<(std::ostream& os, const std::multiset<X>& v) { return printInsts(os, v); }
}
#endif //POLYHOOK_2_0_INSTRUCTION_HPP
