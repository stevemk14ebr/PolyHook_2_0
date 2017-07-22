//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/AllocatedMemoryBlock.hpp"

bool PLH::AllocatedMemoryBlock::operator==(const PLH::AllocatedMemoryBlock& other) const {
    return this->getParentBlock().get() == other.getParentBlock().get() &&
            this->getDescription() == other.getDescription();
}

bool PLH::AllocatedMemoryBlock::operator!=(const PLH::AllocatedMemoryBlock& other) const {
    return !(*this == other);
}

bool PLH::AllocatedMemoryBlock::operator<(const PLH::AllocatedMemoryBlock& other) const {
    return this->getDescription() < other.getDescription();
}

bool PLH::AllocatedMemoryBlock::operator>(const PLH::AllocatedMemoryBlock& other) const {
    return this->getDescription() > other.getDescription();
}

bool PLH::AllocatedMemoryBlock::containsBlock(const PLH::MemoryBlock& other) const {
    return this->getDescription().containsBlock(other);
}

bool PLH::AllocatedMemoryBlock::containsBlock(const PLH::AllocatedMemoryBlock& other) const {
    return this->getDescription().containsBlock(other.getDescription());
}

bool PLH::AllocatedMemoryBlock::operator>=(const PLH::AllocatedMemoryBlock& other) const {
    return this->getDescription() >= other.getDescription();
}

bool PLH::AllocatedMemoryBlock::operator<=(const PLH::AllocatedMemoryBlock* other) const {
    return this->getDescription() <= other->getDescription();
}

PLH::AllocatedMemoryBlock::operator PLH::MemoryBlock() const {
    return this->getDescription();
}

inline std::ostream& operator<<(std::ostream& os, const PLH::AllocatedMemoryBlock& obj) {
    os << std::hex << "{Parent:" << (uint64_t)obj.getParentBlock().get() << std::dec << obj.getDescription() << "}";
    return os;
}
