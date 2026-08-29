typedef unsigned long size_word;

void *malloc(size_word amount);
void free(void *address);

typedef struct Cell {
    char *piece;
    int demand;
} Cell;

static Cell *shared_cell;

static void *reserve(size_word amount)
{
    return malloc(amount);
}

static void relinquish(void *address)
{
    free(address);
}

static void clear_piece(char **slot)
{
    relinquish(*slot);
    *slot = (void *)0;
}

static void clear_cell(Cell **slot)
{
    relinquish(*slot);
    *slot = (void *)0;
}

static int exercise(int demand)
{
    Cell *cell = reserve(sizeof(*cell));

    if (cell == (void *)0) {
        return -1;
    }

    cell->piece = reserve(1U);
    if (cell->piece == (void *)0) {
        relinquish(cell);
        return -1;
    }

    cell->demand = demand;
    shared_cell = cell;

    if (demand > 0) {
        clear_piece(&shared_cell->piece);
        clear_cell(&shared_cell);
        return shared_cell->demand;
    }

    clear_piece(&cell->piece);
    clear_cell(&cell);
    return 0;
}

int main(void)
{
    return exercise(1) == 1 ? 0 : 1;
}
