int neutral_path_guard(int value, int limit) {
    if (value < limit) {
        return value + 1;
    }
    return limit;
}
