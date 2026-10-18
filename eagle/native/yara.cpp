#include <yara.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static bool comma;
static bool security_only;

static void quote(const char *value)
{
    putchar('"');
    for (const unsigned char *ch = reinterpret_cast<const unsigned char *>(value); *ch; ch++)
    {
        if (*ch == '"' || *ch == '\\') printf("\\%c", *ch);
        else if (*ch < 32) printf("\\u%04x", *ch);
        else putchar(*ch);
    }
    putchar('"');
}

static int matched(YR_SCAN_CONTEXT *context, int message, void *data, void *unused)
{
    (void)unused;
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    auto *rule = static_cast<YR_RULE *>(data);
    YR_META *meta;
    YR_STRING *string;
    YR_MATCH *match;
    if (security_only)
    {
        const char *category = "", *name = rule->identifier, *description = "", *severity = "warning";
        yr_rule_metas_foreach(rule, meta) if (meta->type == META_TYPE_STRING)
        {
            if (!strcmp(meta->identifier, "category")) category = meta->string;
            if (!strcmp(meta->identifier, "name")) name = meta->string;
            if (!strcmp(meta->identifier, "description")) description = meta->string;
            if (!strcmp(meta->identifier, "severity")) severity = meta->string;
        }
        if (strcmp(category, "Security")) return CALLBACK_CONTINUE;
        if (comma) putchar(',');
        comma = true;
        printf("{\"rule\":"); quote(rule->identifier);
        printf(",\"name\":"); quote(name);
        printf(",\"description\":"); quote(description);
        printf(",\"severity\":"); quote(severity); putchar('}');
        return CALLBACK_CONTINUE;
    }
    if (comma) putchar(',');
    comma = true;
    printf("{\"rule\":"); quote(rule->identifier);
    printf(",\"meta\":{");
    bool separator = false;
    yr_rule_metas_foreach(rule, meta)
    {
        if (separator) putchar(',');
        separator = true;
        quote(meta->identifier); putchar(':');
        if (meta->type == META_TYPE_STRING) quote(meta->string);
        else if (meta->type == META_TYPE_BOOLEAN) printf("%s", meta->integer ? "true" : "false");
        else printf("%lld", static_cast<long long>(meta->integer));
    }
    printf("},\"strings\":["); separator = false;
    yr_rule_strings_foreach(rule, string)
    {
        if (STRING_IS_PRIVATE(string)) continue;
        yr_string_matches_foreach(context, string, match)
        {
            if (separator) putchar(',');
            separator = true;
            printf("{\"identifier\":"); quote(string->identifier); printf(",\"hex\":\"");
            for (int index = 0; index < match->data_length; index++) printf("%02x", match->data[index]);
            printf("\"}"); break;
        }
    }
    printf("]}");
    return CALLBACK_CONTINUE;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5 || (argc == 5 && strcmp(argv[4], "--security"))) { fputs("usage: eagle-yara RULES FILE [TIMEOUT] [--security]\n", stderr); return 2; }
    security_only = argc == 5;
    char *end = nullptr;
    long timeout = argc >= 4 ? strtol(argv[3], &end, 10) : 30;
    if (timeout < 1 || timeout > 3600 || (end && *end)) { fputs("invalid scan timeout\n", stderr); return 2; }
    int status = yr_initialize();
    if (status) return status;
    YR_COMPILER *compiler = nullptr;
    YR_RULES *rules = nullptr;
    FILE *source = fopen(argv[1], "r");
    if (!source) { fputs("cannot open rule file\n", stderr); yr_finalize(); return 1; }
    status = yr_compiler_create(&compiler);
    if (!status) status = yr_compiler_add_file(compiler, source, nullptr, argv[1]);
    fclose(source);
    if (!status) status = yr_compiler_get_rules(compiler, &rules);
    if (compiler) yr_compiler_destroy(compiler);
    if (status) { fprintf(stderr, "rule compilation failed: %d\n", status); yr_finalize(); return 1; }
    printf("{\"matches\":[");
    status = yr_rules_scan_file(rules, argv[2], 0, matched, nullptr, timeout);
    printf("]}\n");
    yr_rules_destroy(rules); yr_finalize();
    if (status) { fprintf(stderr, "YARA scan failed: %d\n", status); return 1; }
    return 0;
}
