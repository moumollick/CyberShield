// Logger.h - event log (header only)
#pragma once
#include <deque>
#include <string>
#include <vector>

struct LogEntry {
    std::string text;
    float r, g, b;
};

class EventLog {
public:
    std::deque<LogEntry> entries;          // last 200 lines (shown on the dashboard)
    std::vector<std::string> history;      // Week 4: every line, used when saving to file

    void add(const std::string& text, float r, float g, float b) {
        history.push_back(text);
        entries.push_back({text, r, g, b});
        if (entries.size() > 200) entries.pop_front();
    }
    void clear() { entries.clear(); history.clear(); }
};