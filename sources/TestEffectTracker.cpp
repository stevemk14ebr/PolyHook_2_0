#include "headers/Tests/TestEffectTracker.hpp"
#ifdef _WIN32
#define DEBUG_BREAK __debugbreak()
#else
#include <signal.h>
#define DEBUG_BREAK raise(SIGTRAP);
#endif


Effect::Effect() : m_uid(UID::singleton()) {
	m_executed = false;
}

Effect& Effect::operator=(const Effect& rhs) {
	m_uid = rhs.m_uid;
	m_executed = rhs.m_executed;
	return *this;
}

void Effect::trigger() {
	m_executed = true;
}

bool Effect::didExecute() {
	return m_executed;
}

void EffectTracker::PushEffect() {
	m_effectQ.push_back(Effect());
}

Effect EffectTracker::PopEffect() {
	Effect effect = m_effectQ.back();
	m_effectQ.pop_back();
	return effect;
}

Effect& EffectTracker::PeakEffect() {
	if (m_effectQ.size() <= 0) {
		DEBUG_BREAK;
		PushEffect();
	}
		
	return m_effectQ.back();
}

