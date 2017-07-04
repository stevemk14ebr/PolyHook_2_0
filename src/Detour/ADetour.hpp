//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP
#include "src/Detour/x64DetourImpl.hpp"
#include "src/Detour/x86DetourImpl.hpp"

/**All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

template<typename Architecture>
class Detour : public PLH::IHook
{
public:
    using Architecture::GetType;
    using Architecture::DetourBuffer;
    using Architecture::AllocateMemory;

    typedef typename Architecture::DetourBuffer ArchBuffer;

    Detour(const uint64_t fnAddress, const uint64_t fnCallback);
    Detour(const uint8_t* fnAddress, const uint8_t* fnCallback);

    virtual bool Hook() override;
    virtual bool UnHook() override;

    virtual PLH::HookType GetType() override;
private:
    uint64_t hookAddress;
    uint64_t callbackAddress;
    bool hooked;

    ArchBuffer detourBuffer;
    Architecture archImpl;
};


template<typename Architecture>
Detour<Architecture>::Detour(const uint64_t fnAddress, const uint64_t fnCallback) {
    hookAddress = fnAddress;
    callbackAddress = fnCallback;
    hooked = false;
}

template<typename Architecture>
Detour<Architecture>::Detour(const uint8_t* fnAddress, const uint8_t* fnCallback) {
    hookAddress = (uint64_t)fnAddress;
    callbackAddress = (uint64_t)fnCallback;
    hooked = false;
}

template<typename Architecture>
bool Detour<Architecture>::Hook() {
    ArchBuffer buf = Architecture::AllocateMemory(callbackAddress);

}

template<typename Architecture>
bool Detour<Architecture>::UnHook() {

}

template<typename Architecture>
PLH::HookType Detour<Architecture>::GetType() {
    return archImpl.GetType();
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
