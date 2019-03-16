#include "headers/Instruction.hpp"

using namespace PLH;

PLH::Instruction::Instruction(uint64_t address, const Displacement &displacement,
			const uint8_t displacementOffset, const bool isRelative,
			const std::vector<uint8_t> &bytes, const std::string &mnemonic,
			const std::string &opStr)
	: m_address(address), m_displacement(displacement),
	  m_dispOffset(displacementOffset), m_isRelative(isRelative),
	  m_hasDisplacement(false), m_bytes(bytes), m_mnemonic(mnemonic),
	  m_opStr(opStr), m_uid(UID::singleton()) {}

PLH::Instruction::Instruction(uint64_t address, const Displacement &displacement,
			const uint8_t displacementOffset, bool isRelative, uint8_t bytes[],
			size_t arrLen, const std::string &mnemonic,
			const std::string &opStr)
	: Instruction(address, displacement, displacementOffset, isRelative,
				  std::vector<uint8_t>{bytes, bytes + arrLen}, mnemonic,
				  opStr) {}

/**Get the address of where the instruction points if it's a branching
 * instruction
 * @Notes: Handles eip/rip & immediate branches correctly
 * **/
uint64_t PLH::Instruction::getDestination() const {
  if (isDisplacementRelative()) {
	uint64_t dest = m_address + m_displacement.Relative + size();
	return dest;
  }
  return m_displacement.Absolute;
}

void PLH::Instruction::setDestination(const uint64_t dest) {
  if (!isBranching() && !hasDisplacement())
	return;

  if (isDisplacementRelative()) {
	int64_t newRelativeDisp = calculateRelativeDisplacement<int64_t>(
		getAddress(), dest, (uint8_t)size());

	setRelativeDisplacement(newRelativeDisp);
	return;
  }
  setAbsoluteDisplacement(dest);
}

/**Get the address of the instruction in memory**/
uint64_t PLH::Instruction::getAddress() const { return m_address; }

/**Set a new address of the instruction in memory
 @Notes: Doesn't move the instruction, marks it for move on writeEncoding and
 relocates if appropriate**/
void PLH::Instruction::setAddress(const uint64_t address) { m_address = address; }

/**Get the displacement from current address**/
PLH::Instruction::Displacement PLH::Instruction::getDisplacement() const { return m_displacement; }

/**Set where in the instruction bytes the offset is encoded**/
void PLH::Instruction::setDisplacementOffset(const uint8_t offset) { m_dispOffset = offset; }

void PLH::Instruction::setBranching(const bool status) { m_isBranching = status; }

/**Get the offset into the instruction bytes where displacement is encoded**/
uint8_t PLH::Instruction::getDisplacementOffset() const { return m_dispOffset; }

/**Check if displacement is relative to eip/rip**/
bool PLH::Instruction::isDisplacementRelative() const { return m_isRelative; }

/**Check if the instruction is a type with valid displacement**/
bool PLH::Instruction::hasDisplacement() const { return m_hasDisplacement; }

bool PLH::Instruction::isBranching() const {
  if (m_isBranching && m_isRelative) {
	if (!m_hasDisplacement) {
	  DEBUG_BREAK
	  assert(m_hasDisplacement);
	}
  }
  return m_isBranching;
}

const std::vector<uint8_t>& PLH::Instruction::getBytes() const { return m_bytes; }

/**Get short symbol name of instruction**/
std::string PLH::Instruction::getMnemonic() const { return m_mnemonic; }

/**Get symbol name and parameters**/
std::string PLH::Instruction::getFullName() const { return m_mnemonic + " " + m_opStr; }

size_t PLH::Instruction::getDispSize() {
  // jmp (e9 eb be ad de) = 5 bytes, 1 disp off, 4 disp sz
  return size() - getDisplacementOffset();
}

size_t PLH::Instruction::size() const { return m_bytes.size(); }

void PLH::Instruction::setRelativeDisplacement(const int64_t displacement) {
  /**Update our class' book-keeping of this stuff and then modify the byte
   * array. This doesn't actually write the changes to the executeable code, it
   * writes to our copy of the bytes**/
  m_displacement.Relative = displacement;
  m_isRelative = true;
  m_hasDisplacement = true;

  const uint32_t dispSz = (uint32_t)(size() - getDisplacementOffset());
  if (getDisplacementOffset() + dispSz > m_bytes.size() ||
	  dispSz > sizeof(m_displacement.Relative)) {
	DEBUG_BREAK
	return;
  }

  assert(getDisplacementOffset() + dispSz <= m_bytes.size() &&
		 dispSz <= sizeof(m_displacement.Relative));
  std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Relative,
			  dispSz);
}

void PLH::Instruction::setAbsoluteDisplacement(const uint64_t displacement) {
  /** Update our class' book-keeping of this stuff and then modify the byte
   * array. This doesn't actually write the changes to the executeable code, it
   * writes to our copy of the bytes**/
  m_displacement.Absolute = displacement;
  m_isRelative = false;
  m_hasDisplacement = true;

  const uint32_t dispSz = (uint32_t)(size() - getDisplacementOffset());
  if (getDisplacementOffset() + dispSz > m_bytes.size() ||
	  dispSz > sizeof(m_displacement.Absolute)) {
	DEBUG_BREAK
	return;
  }

  assert(getDisplacementOffset() + dispSz <= m_bytes.size() &&
		 dispSz <= sizeof(m_displacement.Absolute));
  std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Absolute,
			  dispSz);
}

long PLH::Instruction::getUID() const { return m_uid.val; }

bool PLH::operator==(const PLH::Instruction& lhs, const PLH::Instruction& rhs) {
	return lhs.getUID() == rhs.getUID();
}

std::ostream& PLH::operator<<(std::ostream& os, const PLH::Instruction& obj) {
	std::stringstream byteStream;
	for (std::size_t i = 0; i < obj.size(); i++)
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

uint16_t PLH::calcInstsSz(const insts_t& insts) {
	uint16_t sz = 0;
	for (const auto& ins : insts)
		sz += (uint16_t)ins.size();
	return sz;
}

std::ostream& PLH::operator<<(std::ostream& os, const insts_t& v) {
	std::for_each(begin(v), end(v),[&os](auto& inst){ os << inst << '\n';});
	return os;
}

PLH::insts_t PLH::makex64PreferredJump(const uint64_t address, const uint64_t destination) {
	PLH::Instruction::Displacement zeroDisp = { 0 };
	uint64_t                       curInstAddress = address;

	std::vector<uint8_t> raxBytes = { 0x50 };
	Instruction pushRax(curInstAddress,
		zeroDisp,
		0,
		false,
		raxBytes,
		"push",
		"rax");
	curInstAddress += pushRax.size();

	std::stringstream ss;
	ss << std::hex << destination;

	std::vector<uint8_t> movRaxBytes;
	movRaxBytes.resize(10);
	movRaxBytes[0] = 0x48;
	movRaxBytes[1] = 0xB8;
	memcpy(&movRaxBytes[2], &destination, 8);

	Instruction movRax(curInstAddress, zeroDisp, 0, false,
		movRaxBytes, "mov", "rax, " + ss.str());
	curInstAddress += movRax.size();

	std::vector<uint8_t> xchgBytes = { 0x48, 0x87, 0x04, 0x24 };
	Instruction xchgRspRax(curInstAddress, zeroDisp, 0, false,
		xchgBytes, "xchg", "QWORD PTR [rsp],rax");
	curInstAddress += xchgRspRax.size();

	std::vector<uint8_t> retBytes = { 0xC3 };
	Instruction ret(curInstAddress, zeroDisp, 0, false,
		retBytes, "ret", "");
	curInstAddress += ret.size();

	return { pushRax, movRax, xchgRspRax, ret };
}

PLH::insts_t PLH::makex64MinimumJump(const uint64_t address, const uint64_t destination, const uint64_t destHolder) {
	PLH::Instruction::Displacement disp = { 0 };
	disp.Relative = PLH::Instruction::calculateRelativeDisplacement<int32_t>(address, destHolder, 6);

	std::vector<uint8_t> destBytes;
	destBytes.resize(8);
	memcpy(destBytes.data(), &destination, 8);
	Instruction specialDest(destHolder, disp, 0, false, destBytes, "dest holder", "");

	std::vector<uint8_t> bytes;
	bytes.resize(6);
	bytes[0] = 0xFF;
	bytes[1] = 0x25;
	memcpy(&bytes[2], &disp.Relative, 4);

	std::stringstream ss;
	ss << std::hex << "[" << destHolder << "] ->" << destination;

	return { Instruction(address, disp, 2, true, bytes, "jmp", ss.str()),  specialDest };
}

PLH::insts_t PLH::makex86Jmp(const uint64_t address, const uint64_t destination) {
	Instruction::Displacement disp;
	disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destination, 5);

	std::vector<uint8_t> bytes(5);
	bytes[0] = 0xE9;
	memcpy(&bytes[1], &disp.Relative, 4);

	std::stringstream ss;
	ss << std::hex << destination;

	return { Instruction(address, disp, 1, true, bytes, "jmp", ss.str()) };
}

PLH::insts_t PLH::makeAgnosticJmp(const uint64_t address, const uint64_t destination) {
	if constexpr (sizeof(char*) == 4)
		return makex86Jmp(address, destination);
	else
		return makex64PreferredJump(address, destination);
}