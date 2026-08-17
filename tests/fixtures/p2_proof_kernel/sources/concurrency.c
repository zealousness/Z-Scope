struct neutral_gate {
    int state;
};

void neutral_lock(struct neutral_gate *gate);
void neutral_unlock(struct neutral_gate *gate);

int neutral_concurrency(int *shared, struct neutral_gate *gate) {
    neutral_lock(gate);
    *shared += 1;
    neutral_unlock(gate);
    return *shared;
}
