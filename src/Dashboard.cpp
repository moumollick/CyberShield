// Dashboard.cpp
#include "Dashboard.h"
#include "Renderer.h"
#include <cstdio>
#include <cmath>
#include <string>

namespace {
    const int PX = 910, PY = 20, PW = 360, PH = 660;   // panel rectangle

    // y of the first rule row (must match the layout in Dashboard::draw)
    float rulesTopY() { return PY + PH - 30 - 30 - 28 - (18 * 3 + 24) - 28 - 18; }

    void text(float x, float y, float r, float g, float b, const std::string& s) {
        Renderer::setColor(r, g, b);
        Renderer::drawText(x, y, s.c_str());
    }
}

// Week 3: packet inspector box (bottom middle of the simulation area)
static void drawInspector(const Network& net) {
    const int cx = 415, cy = 70, hw = 225, hh = 60;
    Renderer::setColor(0.07f, 0.08f, 0.13f);
    Renderer::rectFilled(cx, cy, hw, hh);
    Renderer::setColor(0.3f, 0.35f, 0.5f);
    Renderer::rectOutline(cx, cy, hw, hh);

    float x = cx - hw + 10;
    float y = cy + hh - 16;
    char buf[160];

    text(x, y, 1, 1, 1, "PACKET INSPECTOR");
    y -= 18;

    if (!net.hasSelected) {
        text(x, y, 0.6f, 0.6f, 0.6f, "Click a packet to inspect it");
        y -= 16;
        text(x, y, 0.6f, 0.6f, 0.6f, "(press Space to pause first)");
        return;
    }

    const Packet& p = net.selected;
    std::string srcName = "?";
    if (!p.path.empty()) srcName = net.nodes[p.path[0]].name;

    std::snprintf(buf, sizeof(buf), "#%d  %s  %s -> %s", p.id, srcName.c_str(), p.srcIP.c_str(), p.dstIP.c_str());
    text(x, y, 0.8f, 0.9f, 1, buf);  y -= 16;
    std::snprintf(buf, sizeof(buf), "Port %d  %s  %d bytes", p.port, p.protocol.c_str(), p.size);
    text(x, y, 0.8f, 0.9f, 1, buf);  y -= 16;
    std::snprintf(buf, sizeof(buf), "Signature: %s   Failed login: %s",
                  p.signature.empty() ? "-" : p.signature.c_str(), p.failedLogin ? "yes" : "no");
    text(x, y, 0.8f, 0.9f, 1, buf);  y -= 16;

    const char* st = "Moving";
    float r = 0.3f, g = 0.7f, b = 1.0f;
    switch (p.state) {
        case ALLOWED:      st = "ALLOWED";      r = 0.3f; g = 1.0f; b = 0.4f; break;
        case BLOCKED:      st = "BLOCKED";      r = 1.0f; g = 0.3f; b = 0.3f; break;
        case RATE_LIMITED: st = "RATE-LIMITED"; r = 1.0f; g = 0.9f; b = 0.1f; break;
        case DONE:         st = "finished";     r = 0.6f; g = 0.6f; b = 0.6f; break;
        default: break;
    }
    std::snprintf(buf, sizeof(buf), "State: %s%s", st, net.selectedGone ? " (gone from network)" : "");
    text(x, y, r, g, b, buf);  y -= 16;

    if (p.matchedRule.empty()) {
        text(x, y, 0.7f, 0.7f, 0.7f, "Rule: not inspected yet (before firewall)");
        return;
    }
    const Rule* rule = net.firewall.findRule(p.matchedRule);
    std::snprintf(buf, sizeof(buf), "Rule: %s - %s", p.matchedRule.c_str(), rule ? rule->description.c_str() : "");
    text(x, y, 1, 1, 1, buf);  y -= 16;
    std::snprintf(buf, sizeof(buf), "Threat: %s", p.threat.c_str());
    text(x, y, r, g, b, buf);
}

void Dashboard::draw(const Network& net, const AttackGenerator& atk) {
    drawInspector(net);
    // panel background + border
    Renderer::setColor(0.07f, 0.08f, 0.13f);
    Renderer::rectFilled(PX + PW / 2, PY + PH / 2, PW / 2, PH / 2);
    Renderer::setColor(0.3f, 0.35f, 0.5f);
    Renderer::rectOutline(PX + PW / 2, PY + PH / 2, PW / 2, PH / 2);

    float x = PX + 15;
    float y = PY + PH - 30;
    char buf[128];

    text(x, y, 1, 1, 1, "SECURITY DASHBOARD");
    y -= 30;

    // status
    const char* st = "SAFE";
    float sr = 0.2f, sg = 1.0f, sb = 0.3f;
    if (net.status() == STATUS_WARNING)  { st = "WARNING";  sr = 1.0f; sg = 0.8f; sb = 0.1f; }
    if (net.status() == STATUS_CRITICAL) { st = "CRITICAL"; sr = 1.0f; sg = 0.2f; sb = 0.2f; }
    Renderer::setColor(sr, sg, sb);
    Renderer::rectFilled((int)x + 6, (int)y + 4, 6, 6);
    std::snprintf(buf, sizeof(buf), "STATUS: %s", st);
    text(x + 20, y, sr, sg, sb, buf);
    y -= 28;

    // counters
    std::snprintf(buf, sizeof(buf), "Total inspected : %d", net.totalPackets);
    text(x, y, 1, 1, 1, buf);                   y -= 18;
    std::snprintf(buf, sizeof(buf), "Allowed         : %d", net.allowedCount);
    text(x, y, 0.3f, 1, 0.4f, buf);             y -= 18;
    std::snprintf(buf, sizeof(buf), "Blocked         : %d", net.blockedCount);
    text(x, y, 1, 0.3f, 0.3f, buf);             y -= 18;
    std::snprintf(buf, sizeof(buf), "Rate-limited    : %d", net.rateLimitedCount);
    text(x, y, 1, 0.9f, 0.1f, buf);             y -= 24;

    // active attack
    std::snprintf(buf, sizeof(buf), "Attack: %s", AttackGenerator::name(atk.current));
    text(x, y, 1, 0.55f, 0.1f, buf);
    y -= 28;

    // firewall rules
    text(x, y, 1, 1, 1, "FIREWALL RULES  (click / F1-F7)");
    y -= 18;
    for (const auto& r : net.firewall.rules) {
        std::snprintf(buf, sizeof(buf), "%s %-3s %s", r.id.c_str(), r.enabled ? "ON" : "OFF", r.description.c_str());
        if (r.enabled) text(x, y, 0.75f, 0.85f, 1.0f, buf);
        else           text(x, y, 0.4f, 0.4f, 0.4f, buf);
        y -= 16;
    }
    y -= 14;

    // Week 5: limit editor
    text(x, y, 1, 1, 1, "LIMITS  (arrow keys)");
    y -= 17;
    for (int i = 0; i < Firewall::PARAM_COUNT; i++) {
        std::snprintf(buf, sizeof(buf), "%s %-18s %s", i == net.editParam ? ">" : " ",
                      net.firewall.paramName(i), net.firewall.paramText(i).c_str());
        if (i == net.editParam) text(x, y, 1.0f, 0.85f, 0.2f, buf);
        else                    text(x, y, 0.6f, 0.7f, 0.9f, buf);
        y -= 16;
    }
    y -= 14;

    // event log (newest first)
    text(x, y, 1, 1, 1, "EVENT LOG");
    y -= 18;
    for (auto it = net.log.entries.rbegin(); it != net.log.entries.rend(); ++it) {
        if (y < PY + 10) break;
        std::string s = it->text;
        if (s.size() > 50) s = s.substr(0, 50);
        text(x, y, it->r, it->g, it->b, s);
        y -= 16;
    }
}

bool Dashboard::inPanel(int mx) { return mx >= PX; }

int Dashboard::ruleAt(int mx, int myGL) {
    if (mx < PX || mx > PX + PW) return -1;
    for (int i = 0; i < 7; i++) {
        float rowY = rulesTopY() - 16.0f * i;
        if (myGL >= rowY - 5 && myGL <= rowY + 11) return i;
    }
    return -1;
}

// Week 4: summary overlay
void Dashboard::drawSummary(const Network& net) {
    const int cx = 450, cy = 350, hw = 330, hh = 260;
    Renderer::setColor(0.05f, 0.06f, 0.10f);
    Renderer::rectFilled(cx, cy, hw, hh);
    Renderer::setColor(0.4f, 0.5f, 0.8f);
    Renderer::rectOutline(cx, cy, hw, hh);

    float x = cx - hw + 20;
    float y = cy + hh - 28;
    char buf[160];

    text(x, y, 1, 1, 1, "SIMULATION SUMMARY   (S: close, L: save log)");
    y -= 28;

    int stopped = net.blockedCount + net.rateLimitedCount;
    float pct = net.totalPackets > 0 ? 100.0f * stopped / net.totalPackets : 0.0f;
    std::snprintf(buf, sizeof(buf), "Inspected %d   Allowed %d   Blocked %d   Rate-limited %d",
                  net.totalPackets, net.allowedCount, net.blockedCount, net.rateLimitedCount);
    text(x, y, 0.8f, 0.9f, 1, buf);  y -= 17;
    std::snprintf(buf, sizeof(buf), "Stopped or throttled: %.0f%% of all packets   (time %.0f s)", pct, net.simTime);
    text(x, y, 0.8f, 0.9f, 1, buf);  y -= 28;

    text(x, y, 1, 1, 1, "RULE HITS");  y -= 17;
    for (int i = 0; i < 7; i++) {
        const Rule& r = net.firewall.rules[i];
        std::snprintf(buf, sizeof(buf), "%s %-3s %-30s %d", r.id.c_str(), r.enabled ? "ON" : "OFF",
                      r.description.c_str(), net.ruleHits[i]);
        if (r.enabled) text(x, y, 0.75f, 0.85f, 1.0f, buf);
        else           text(x, y, 0.45f, 0.45f, 0.45f, buf);
        y -= 16;
    }
    y -= 12;

    text(x, y, 1, 1, 1, "ATTACKS");  y -= 17;
    bool any = false;
    for (int t = 1; t <= 6; t++) {
        if (net.atkSeen[t] == 0) continue;
        any = true;
        int passed = net.atkSeen[t] - net.atkBlocked[t] - net.atkLimited[t];
        std::snprintf(buf, sizeof(buf), "%-18s seen %-3d blocked %-3d limited %-3d passed %d",
                      AttackGenerator::name((AttackType)t), net.atkSeen[t], net.atkBlocked[t],
                      net.atkLimited[t], passed);
        text(x, y, passed > 0 ? 1.0f : 0.4f, passed > 0 ? 0.7f : 1.0f, passed > 0 ? 0.2f : 0.5f, buf);
        y -= 16;
    }
    if (!any) { text(x, y, 0.6f, 0.6f, 0.6f, "No attacks yet (press D for the demo)"); y -= 16; }
    y -= 12;

    std::snprintf(buf, sizeof(buf), "IDS alerts raised: %d", net.alertCount);
    text(x, y, 1.0f, 0.5f, 1.0f, buf);
    y -= 18;

    int best = net.mostTriggeredRule();
    if (best >= 0) {
        std::snprintf(buf, sizeof(buf), "Most triggered rule: %s - %s (%d hits)",
                      net.firewall.rules[best].id.c_str(), net.firewall.rules[best].description.c_str(),
                      net.ruleHits[best]);
        text(x, y, 1, 0.8f, 0.2f, buf);
    }
}

// Week 5: overlay = critical border flash, IDS alert popups, threat gauge
void Dashboard::drawOverlay(const Network& net) {
    // 1) red border flash when the status is CRITICAL
    if (net.status() == STATUS_CRITICAL && std::fmod(net.simTime, 0.8f) < 0.4f) {
        Renderer::setColor(1.0f, 0.15f, 0.15f);
        for (int k = 0; k < 4; k++)
            Renderer::rectOutline(640, 350, 638 - k, 348 - k);
    }

    // 2) IDS alert popups (top middle of the simulation area)
    int row = 0;
    for (const auto& a : net.alerts) {
        float f = a.timeLeft < 1.0f ? a.timeLeft : 1.0f;      // fade out in the last second
        int cy = 600 - row * 30;
        Renderer::setColor(0.25f * f, 0.05f * f, 0.25f * f);
        Renderer::rectFilled(570, cy, 150, 12);
        Renderer::setColor(1.0f * f, 0.4f * f, 1.0f * f);
        Renderer::rectOutline(570, cy, 150, 12);
        std::string s = "ALERT: " + a.text;
        if (s.size() > 34) s = s.substr(0, 34);
        Renderer::drawText(425, cy - 4, s.c_str());
        row++;
    }

    // 3) threat gauge (half circle made of ticks + needle)
    const int gx = 760, gy = 75, R = 40;
    float v = net.threatLevel / 10.0f;
    if (v > 1.0f) v = 1.0f;
    const float PI = 3.14159265f;
    for (int k = 0; k <= 18; k++) {
        float frac = k / 18.0f;
        float ang = PI - PI * frac;
        float r = 0.2f, g = 0.9f, b = 0.3f;
        if (frac >= 0.8f)      { r = 1.0f; g = 0.2f; b = 0.2f; }
        else if (frac >= 0.25f){ r = 1.0f; g = 0.85f; b = 0.1f; }
        float dim = (frac <= v) ? 1.0f : 0.3f;
        Renderer::setColor(r * dim, g * dim, b * dim);
        Renderer::lineBresenham(gx + (int)(std::cos(ang) * (R - 9)), gy + (int)(std::sin(ang) * (R - 9)),
                                gx + (int)(std::cos(ang) * R),       gy + (int)(std::sin(ang) * R));
    }
    float na = PI - PI * v;
    Renderer::setColor(1, 1, 1);
    Renderer::lineBresenham(gx, gy, gx + (int)(std::cos(na) * (R - 14)), gy + (int)(std::sin(na) * (R - 14)));
    Renderer::circleMidpoint(gx, gy, 4);
    Renderer::drawText(gx - 24, gy - 22, "THREAT LEVEL");
}