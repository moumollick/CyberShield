// AttackGenerator.h
#pragma once
#include <string>

class Network;

enum AttackType {
    ATK_NONE, ATK_FLOOD, ATK_PORTSCAN, ATK_MALWARE,
    ATK_BRUTE, ATK_OVERSIZE, ATK_BLACKLIST
};

class AttackGenerator {
public:
    AttackType current = ATK_NONE;

    void start(AttackType t, Network& net);
    void update(float dt, Network& net);
    void reset() { current = ATK_NONE; remaining = 0; demoActive = false; demoFinished = false; }
    bool active() const { return current != ATK_NONE; }
    static const char* name(AttackType t);

    // Week 4: automatic demo scenario
    bool demoActive = false;
    bool demoFinished = false;       // set when the demo ends (main.cpp then shows the summary)
    void startDemo(Network& net);

private:
    int remaining = 0;
    int src = 0;
    int index = 0;
    float interval = 0.1f;
    float timer = 0;
    float demoTime = 0;
    float demoNormalTimer = 0;
    int   demoStep = 0;

    void spawnOne(Network& net);
};