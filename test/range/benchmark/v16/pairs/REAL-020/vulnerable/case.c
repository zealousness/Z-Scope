static int get_value(int *marker)
{
    *marker = 1;
    return 0;
}

static void note_failure(void)
{
}

static int run_check(void)
{
    int marker = 0;
    int status = get_value(&marker);

    if (status != 0 || marker != 0) {
        note_failure();
        return status;
    }

    return 0;
}

int main(void)
{
    return run_check();
}
