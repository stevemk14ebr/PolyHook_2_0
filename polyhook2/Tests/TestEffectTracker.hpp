#ifndef POLYHOOK_2_0_EFFECTSTRACKER_HPP
#define POLYHOOK_2_0_EFFECTSTRACKER_HPP

#include <vector>

#include "../UID.hpp"

class Effect {
public:
	Effect();

	Effect& operator=(const Effect& rhs);

	void trigger();

	bool didExecute();
private:
	bool m_executed;
	PLH::UID m_uid;
};

/**Track if some side effect happened.**/
class EffectTracker {
public:
	void PushEffect();
	Effect PopEffect();
	Effect& PeakEffect();
private:
	std::vector<Effect> m_effectQ;
};
#endif