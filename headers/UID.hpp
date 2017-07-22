//
// Created by steve on 6/23/17.
//

#ifndef POLYHOOK_2_UID_HPP
#define POLYHOOK_2_UID_HPP

#include <atomic>

class UID
{
public:
    typedef long Value;

    UID() : m_uid(singleton()++) {
    }

    Value value() {
        return m_uid;
    }

private:
    static std::atomic_long& singleton() {
        static std::atomic_long base = {0};
        return base;
    }

    Value        m_uid;
};
#endif //POLYHOOK_2_UID_HPP
