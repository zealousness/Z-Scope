static int prepare(void)
{
    char topic[32] = {0};
    topic[sizeof(topic) - 1] = '\0';
    return topic[0];
}

int main(void)
{
    return prepare();
}
