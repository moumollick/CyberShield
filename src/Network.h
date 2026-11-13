// Network.h - UPDATED for Week 4
#pragma once
#include <vector>
#include <utility>
#include <string>
#include "Node.h"
#include "Packet.h"
#include "Firewall.h"
#include "Logger.h"

enum SecurityStatus { STATUS_SAFE, STATUS_WARNING, STATUS_CRITICAL };

class Network {
public:
    // node index layout: 0-5 clients, 6 firewall, 7 DMZ web server, 8 internal server
    static constexpr int FIREWALL_IDX = 6;
    static constexpr int DMZ_IDX      = 7;
    static constexpr int INTERNAL_IDX = 8;

    std::vector<Node> nodes;
    std::vector<std::pair<int,int>> links;
    std::vector<Packet> packets;

    Firewall firewall;
    EventLog log;

    // statistics (counted when a packet reaches the firewall)
    int totalPackets = 0;
    int allowedCount = 0;
    int blockedCount = 0;
    int rateLimitedCount = 0;

    // Week 4: statistics for the summary screen
    int ruleHits[7]    = {0};   // how many times R1..R7 decided a packet
    int atkSeen[7]     = {0};   // attack packets per AttackType (index 1..6)
    int atkBlocked[7]  = {0};
    int atkLimited[7]  = {0};

    // Week 3: packet inspector (click a packet to select it)
    int    nextId = 1;
    bool   hasSelected = false;   // something is selected
    bool   selectedGone = false;  // selected packet already finished / was removed
    Packet selected;              // copy of the selected packet (kept after it disappears)
    bool   configLoaded = false;

    float simTime = 0;
    float threatLevel = 0;      // rises on block/rate-limit, decays over time

    void init();
    void reset();
    void draw() const;
    void update(float dt);      // dt in seconds

    Packet createPacket(int client, int dest);   // normal-looking packet
    void spawnPacket(const Packet& p);
    void sendNormalPacket();

    SecurityStatus status() const;

    void selectAt(float x, float y);   // click on the simulation area
    void toggleRule(int index);        // enable / disable R1..R6 at runtime

    bool saveLog(const std::string& path);   // Week 4: summary + all events -> text file
    int  mostTriggeredRule() const;          // index 0..5 (R7 ignored), or -1 if no rule fired

private:
    void drawNode(const Node& n) const;
    void drawPacket(const Packet& p) const;
    void onReachFirewall(Packet& p);
};