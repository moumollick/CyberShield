// IDS.cpp - Week 5
#include "IDS.h"
#include <algorithm>

void IDS::reset() {
    portHistory.clear();
    packetTimes.clear();
    failTimes.clear();
    lastAlert.clear();
}

bool IDS::cooledDown(const std::string& key, float now) {
    auto it = lastAlert.find(key);
    if (it != lastAlert.end() && now - it->second < 8.0f) return false;
    lastAlert[key] = now;
    return true;
}

bool IDS::observe(const Packet& p, const Decision& d, float now,
                  const std::string& srcName, std::string& text) {
    const std::string& src = p.srcIP;

    // 1) Port scan: 6 different destination ports from one source within 3 seconds
    {
        auto& h = portHistory[src];
        h.push_back({now, p.port});
        h.erase(std::remove_if(h.begin(), h.end(),
                [now](const Seen& s) { return now - s.time > 3.0f; }), h.end());
        std::set<int> distinct;
        for (const auto& s : h) distinct.insert(s.value);
        if (distinct.size() >= 6 && cooledDown("scan|" + src, now)) {
            text = "Port scan from " + srcName;
            return true;
        }
    }

    // 2) Flood: 12 or more packets from one source within 1 second
    {
        auto& t = packetTimes[src];
        t.push_back(now);
        t.erase(std::remove_if(t.begin(), t.end(),
                [now](float x) { return now - x > 1.0f; }), t.end());
        if (t.size() >= 12 && cooledDown("flood|" + src, now)) {
            text = "DDoS flood from " + srcName;
            return true;
        }
    }

    // 3) Brute force: 3 failed logins from one source within 10 seconds
    if (p.failedLogin) {
        auto& f = failTimes[src];
        f.push_back(now);
        f.erase(std::remove_if(f.begin(), f.end(),
                [now](float x) { return now - x > 10.0f; }), f.end());
        if (f.size() >= 3 && cooledDown("brute|" + src, now)) {
            text = "Brute force from " + srcName;
            return true;
        }
    }

    // 4) Suspicious payload (any signature)
    if (!p.signature.empty() && cooledDown("payload|" + src, now)) {
        text = "Malware payload from " + srcName;
        return true;
    }

    // 5) Oversized packet
    if (p.size > 3000 && cooledDown("size|" + src, now)) {
        text = "Oversized pkt from " + srcName;
        return true;
    }

    // 6) Blacklisted source (decision of rule R1)
    if (d.ruleId == "R1" && cooledDown("black|" + src, now)) {
        text = "Blacklisted host " + src;
        return true;
    }
    return false;
}