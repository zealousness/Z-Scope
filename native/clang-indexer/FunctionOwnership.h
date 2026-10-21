#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

// Sweep interval endpoints once. Nested/overlapping definitions retain the
// original rule: smallest containing range, then earliest declaration on ties.
class FunctionOwnership {
  using Offset = std::uint64_t;
  using Choice = std::pair<Offset, std::size_t>;
  using Event = std::tuple<Offset, bool, Choice>;
  std::map<std::string, std::vector<std::pair<Offset, std::size_t>>> segments;

public:
  static constexpr std::size_t missing = std::numeric_limits<std::size_t>::max();

  template <class Ranges> void build(const Ranges &ranges) {
    segments.clear();
    std::map<std::string, std::vector<Event>> events;
    for (std::size_t i = 0; i < ranges.size(); ++i) {
      const auto &range = ranges[i];
      if (range.begin > range.end) continue;
      Choice choice{Offset(range.end) - range.begin, i};
      events[range.file].emplace_back(range.begin, true, choice);
      events[range.file].emplace_back(Offset(range.end) + 1, false, choice);
    }
    for (auto &file : events) {
      auto &changes = file.second;
      std::sort(changes.begin(), changes.end());
      std::set<Choice> active;
      auto &result = segments[file.first];
      for (std::size_t i = 0; i < changes.size();) {
        Offset at = std::get<0>(changes[i]);
        do {
          const auto &change = changes[i++];
          if (std::get<1>(change)) active.insert(std::get<2>(change));
          else active.erase(std::get<2>(change));
        } while (i < changes.size() && std::get<0>(changes[i]) == at);
        std::size_t winner = active.empty() ? missing : active.begin()->second;
        if (result.empty() || result.back().second != winner)
          result.emplace_back(at, winner);
      }
    }
  }

  std::size_t find(const std::string &file, unsigned offset) const {
    auto found = segments.find(file);
    if (found == segments.end()) return missing;
    const auto &values = found->second;
    auto next = std::upper_bound(values.begin(), values.end(), Offset(offset),
                                [](Offset at, const auto &value) { return at < value.first; });
    return next == values.begin() ? missing : std::prev(next)->second;
  }
};
