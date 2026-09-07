#include "FunctionOwnership.h"
#include <cassert>
#include <random>

struct Range { std::string file; unsigned begin, end; };

int main() {
  std::vector<Range> ranges{{"a", 0, 100}, {"a", 3, 5}, {"a", 3, 5},
                            {"a", 5, 8}, {"b", 3, 5}, {"a", 11, 10}};
  std::mt19937 random(0);
  for (unsigned i = 0; i < 2000; ++i) {
    unsigned begin = random() % 500, end = random() % 500;
    ranges.push_back({i % 2 ? "a" : "b", begin, end});
  }
  FunctionOwnership index;
  index.build(ranges);
  for (const auto &file : {"a", "b", "absent"}) {
    for (unsigned at = 0; at < 600; ++at) {
      std::size_t expected = FunctionOwnership::missing;
      for (std::size_t i = 0; i < ranges.size(); ++i) {
        const auto &r = ranges[i];
        if (r.file == file && r.begin <= at && at <= r.end &&
            (expected == FunctionOwnership::missing || r.end-r.begin < ranges[expected].end-ranges[expected].begin)) expected = i;
      }
      assert(index.find(file, at) == expected);
    }
  }
  ranges.clear();
  for (unsigned i = 0; i < 50000; ++i) ranges.push_back({"large", i * 4, i * 4 + 2});
  index.build(ranges);
  for (unsigned i = 0; i < 50000; ++i) assert(index.find("large", i * 4 + 1) == i);
}
