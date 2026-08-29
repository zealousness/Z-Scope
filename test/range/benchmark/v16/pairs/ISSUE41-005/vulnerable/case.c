enum {
    ACCEPTED_KIND = 1,
    SPECIAL_LEVEL = 1
};

int decide(int detected_kind, int access_level)
{
    if (detected_kind != ACCEPTED_KIND &&
        access_level == SPECIAL_LEVEL) {
        return -1;
    }
    return 0;
}

int main(void)
{
    return decide(ACCEPTED_KIND + 1,
                  SPECIAL_LEVEL - 1) == -1 ? 0 : 1;
}
