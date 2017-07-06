//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/AllocatedMemoryBlock.hpp"

bool PLH::AllocatedMemoryBlock::operator==(const PLH::AllocatedMemoryBlock& other) const {
    return this->GetParentBlock().get() == other.GetParentBlock().get() &&
           this->GetDescription() == other.GetDescription();
}

bool PLH::AllocatedMemoryBlock::operator!=(const PLH::AllocatedMemoryBlock& other) const {
    return !(*this == other);
}

bool PLH::AllocatedMemoryBlock::operator<(const PLH::AllocatedMemoryBlock& other) const {
    return this->GetDescription() < other.GetDescription();
}

bool PLH::AllocatedMemoryBlock::operator>(const PLH::AllocatedMemoryBlock& other) const {
    return this->GetDescription() > other.GetDescription();
}

bool PLH::AllocatedMemoryBlock::ContainsBlock(const PLH::MemoryBlock& other) const {
    return this->GetDescription().ContainsBlock(other);
}

bool PLH::AllocatedMemoryBlock::ContainsBlock(const PLH::AllocatedMemoryBlock& other) const {
    return this->GetDescription().ContainsBlock(other.GetDescription());
}

bool PLH::AllocatedMemoryBlock::operator>=(const PLH::AllocatedMemoryBlock& other) const {
    return this->GetDescription() >= other.GetDescription();
}

bool PLH::AllocatedMemoryBlock::operator<=(const PLH::AllocatedMemoryBlock* other) const {
    return this->GetDescription() <= other->GetDescription();
}

PLH::AllocatedMemoryBlock::operator PLH::MemoryBlock() const {
    return this->GetDescription();
}

inline std::ostream& operator<<(std::ostream& os, const PLH::AllocatedMemoryBlock& obj) {
    os << std::hex << "{Parent:" << (uint64_t)obj.GetParentBlock().get() << std::dec << obj.GetDescription() << "}";
    return os;
}
