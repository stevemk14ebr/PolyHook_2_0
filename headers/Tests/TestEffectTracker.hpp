#pragma once
#include <vector>

#include "../UID.hpp"

class Effect {
public:
	Effect() : m_uid(UID::singleton()) {
		m_executed = false;
	}

	Effect& operator=(const Effect& rhs) {
		m_uid = rhs.m_uid;
		m_executed = rhs.m_executed;
		return *this;
	}

	void trigger() {
		m_executed = true;
	}

	bool didExecute() {
		return m_executed;
	}
private:
	bool m_executed;
	UID m_uid;
};

/**Track if some side effect happened.**/
class EffectTracker {
public:
	void PushEffect() {
		m_effectQ.push_back(Effect());
	}

	Effect PopEffect() {
		Effect effect = m_effectQ.back();
		m_effectQ.pop_back();
		return effect;
	}

	Effect& PeakEffect() {
		return m_effectQ.back();
	}
private:
	std::vector<Effect> m_effectQ;
};