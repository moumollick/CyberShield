// IDS.h - Week 5: simple intrusion detection (pattern based, separate from the firewall rules)
// The firewall decides per packet. The IDS looks at behaviour over time
// (many ports, many packets per second, repeated failed logins) and raises alerts.
#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>
#include "Packet.h"
#include "Firewall.h"

class IDS {
public:
    void reset();

    // Look at one packet. Returns true and fills 'text' when a NEW alert should be shown.
    bool observe(const Packet& p, const Decision& d, float now,
                 const std::string& srcName, std::string& text);

private:
    struct Seen { float time; int value; };
    std::map<std::string, std::vector<Seen>> portHistory;    // per source: destination ports
    std::map<std::string, std::vector<float>> packetTimes;   // per source: packet arrival times
    std::map<std::string, std::vector<float>> failTimes;     // per source: failed logins
    std::map<std::string, float> lastAlert;                  // "type|source" -> time of last alert

    bool cooledDown(const std::string& key, float now);      // avoids alert spam (8 s per key)
};