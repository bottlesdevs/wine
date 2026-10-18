#include <glib.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>

static std::string field(json_object *object, const char *name)
{
    json_object *value = nullptr;
    if (!json_object_object_get_ex(object, name, &value) || !value) return "";
    if (!json_object_is_type(value, json_type_string)) throw std::runtime_error("lookup fields must be strings");
    return json_object_get_string(value);
}

static std::string fold(const std::string &value)
{
    if (!g_utf8_validate(value.data(), value.size(), nullptr)) throw std::runtime_error("invalid UTF-8 name");
    gchar *text = g_utf8_casefold(value.c_str(), value.size());
    std::string result(text); g_free(text); return result;
}

static std::string normalize(const std::string &value)
{
    std::string text = fold(value), result;
    bool space = false;
    unsigned char previous = 0;
    for (unsigned char ch : text)
    {
        bool letter = ch >= 'a' && ch <= 'z', digit = ch >= '0' && ch <= '9';
        if (!letter && !digit) { space = !result.empty(); previous = 0; continue; }
        if ((letter && previous >= '0' && previous <= '9') || (digit && previous >= 'a' && previous <= 'z')) space = true;
        if (space && !result.empty()) result += ' ';
        result += ch; space = false; previous = ch;
    }
    return result;
}

static std::vector<std::string> numbers(const std::string &name)
{
    std::vector<std::string> result;
    for (size_t i = 0; i < name.size();)
    {
        if (name[i] < '0' || name[i] > '9') { i++; continue; }
        size_t start = i;
        while (i < name.size() && name[i] >= '0' && name[i] <= '9') i++;
        result.push_back(name.substr(start, i-start));
    }
    return result;
}

static double ratio(const std::string &a, const std::string &b)
{
    if (a.empty() && b.empty()) return 1;
    std::map<char, std::vector<size_t>> positions;
    for (size_t i = 0; i < b.size(); i++) positions[b[i]].push_back(i);
    if (b.size() >= 200)
    {
        for (auto it = positions.begin(); it != positions.end();)
            if (it->second.size() > b.size()/100 + 1) it = positions.erase(it); else ++it;
    }
    struct range { size_t alo, ahi, blo, bhi; };
    std::vector<range> queue = {{0, a.size(), 0, b.size()}};
    size_t total = 0;
    while (!queue.empty())
    {
        auto part = queue.back(); queue.pop_back();
        size_t best_a = part.alo, best_b = part.blo, best = 0;
        std::map<size_t, size_t> previous;
        for (size_t i = part.alo; i < part.ahi; i++)
        {
            std::map<size_t, size_t> current;
            auto found = positions.find(a[i]);
            if (found != positions.end()) for (size_t j : found->second)
            {
                if (j < part.blo) continue;
                if (j >= part.bhi) break;
                size_t length = 1;
                if (j) { auto older = previous.find(j-1); if (older != previous.end()) length += older->second; }
                current[j] = length;
                if (length > best) { best = length; best_a = i-length+1; best_b = j-length+1; }
            }
            previous.swap(current);
        }
        while (best_a > part.alo && best_b > part.blo && a[best_a-1] == b[best_b-1]) { best_a--; best_b--; best++; }
        while (best_a + best < part.ahi && best_b + best < part.bhi && a[best_a+best] == b[best_b+best]) best++;
        if (!best) continue;
        total += best;
        if (part.alo < best_a && part.blo < best_b) queue.push_back({part.alo, best_a, part.blo, best_b});
        if (best_a+best < part.ahi && best_b+best < part.bhi) queue.push_back({best_a+best, part.ahi, best_b+best, part.bhi});
    }
    return 2.0 * total / (a.size()+b.size());
}

static json_object *member(json_object *object, const char *name);

class database
{
    sqlite3 *connection = nullptr;
public:
    explicit database(const char *path)
    {
        struct stat info;
        if (stat(path, &info) || !S_ISREG(info.st_mode)) throw std::runtime_error("Intel database must be a regular file");
        if (sqlite3_open_v2(path, &connection, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        { if (connection) sqlite3_close(connection); throw std::runtime_error("cannot open Intel database read-only"); }
    }
    ~database() { sqlite3_close(connection); }
    std::vector<json_object *> query(const char *sql, const std::string &value = "")
    {
        sqlite3_stmt *statement = nullptr;
        if (sqlite3_prepare_v2(connection, sql, -1, &statement, nullptr) != SQLITE_OK) throw std::runtime_error("Intel query preparation failed");
        if (sqlite3_bind_parameter_count(statement)) sqlite3_bind_text(statement, 1, value.data(), value.size(), SQLITE_TRANSIENT);
        std::vector<json_object *> rows;
        int status;
        while ((status = sqlite3_step(statement)) == SQLITE_ROW)
        {
            auto *row = json_object_new_object();
            for (int index = 0; index < sqlite3_column_count(statement); index++)
            {
                json_object *item = nullptr;
                int type = sqlite3_column_type(statement, index);
                if (type == SQLITE_INTEGER) item = json_object_new_int64(sqlite3_column_int64(statement, index));
                else if (type == SQLITE_FLOAT) item = json_object_new_double(sqlite3_column_double(statement, index));
                else if (type != SQLITE_NULL) item = json_object_new_string(reinterpret_cast<const char *>(sqlite3_column_text(statement, index)));
                json_object_object_add(row, sqlite3_column_name(statement, index), item);
            }
            rows.push_back(row);
        }
        sqlite3_finalize(statement);
        if (status != SQLITE_DONE) { for (auto *row : rows) json_object_put(row); throw std::runtime_error("Intel query failed"); }
        return rows;
    }
    std::string id(const char *sql, const std::string &value)
    {
        auto rows = query(sql, value);
        std::string result;
        if (!rows.empty())
        {
            json_object *number = nullptr;
            json_object_object_get_ex(rows[0], "id", &number);
            result = json_object_get_string(number);
        }
        for (auto *row : rows) json_object_put(row);
        return result;
    }
    json_object *trick(const std::string &name)
    {
        auto rows = query("SELECT name, kind, title, files_json, overrides_json, winver, bottles_dep FROM trick WHERE name = ?", name);
        return rows.empty() ? nullptr : rows[0];
    }
    json_object *status()
    {
        auto rows = query("SELECT name FROM sqlite_schema WHERE type = 'table'");
        std::set<std::string> tables;
        for (auto *row : rows) { tables.insert(field(row, "name")); json_object_put(row); }
        for (const char *name : {"artifact", "meta", "report_agg", "software", "trick", "tweak"})
            if (!tables.count(name)) throw std::runtime_error("Intel database is missing required tables");
        rows = query("SELECT value FROM meta WHERE key = 'schema_version'");
        bool valid = !rows.empty() && json_object_is_type(member(rows[0], "value"), json_type_string) && field(rows[0], "value") == "1";
        for (auto *row : rows) json_object_put(row);
        if (!valid) throw std::runtime_error("unsupported Intel schema");
        rows = query("SELECT EXISTS(SELECT 1 FROM artifact) AS present");
        bool artifacts = !rows.empty() && json_object_get_boolean(member(rows[0], "present"));
        for (auto *row : rows) json_object_put(row);
        auto *result = json_object_new_object();
        json_object_object_add(result, "available", json_object_new_boolean(true));
        json_object_object_add(result, "has_artifacts", json_object_new_boolean(artifacts));
        json_object_object_add(result, "schema_version", json_object_new_string("1"));
        return result;
    }

    json_object *lookup(json_object *request)
    {
        auto schema = query("SELECT value FROM meta WHERE key = 'schema_version'");
        if (schema.empty() || field(schema[0], "value") != "1") { for (auto *row : schema) json_object_put(row); throw std::runtime_error("unsupported Intel schema"); }
        for (auto *row : schema) json_object_put(row);
        std::string software_id, level;
        for (const char *name : {"sha256", "imphash", "steam_appid"})
        {
            std::string value = field(request, name);
            if (value.empty()) continue;
            std::string sql = std::string(name) == "steam_appid" ? "SELECT id FROM software WHERE steam_appid = ?" : "SELECT software_id AS id FROM artifact WHERE " + std::string(name) + " = ? AND software_id IS NOT NULL LIMIT 1";
            software_id = id(sql.c_str(), value);
            if (!software_id.empty()) { level = name; break; }
        }
        std::vector<std::string> candidates;
        std::string product = field(request, "product_name");
        if (!product.empty() && fold(product) != "unknown") candidates.push_back(product);
        json_object *names = nullptr;
        if (json_object_object_get_ex(request, "names", &names) && names)
        {
            if (!json_object_is_type(names, json_type_array)) throw std::runtime_error("names must be an array");
            for (size_t i = 0; i < json_object_array_length(names); i++)
            {
                auto *item = json_object_array_get_idx(names, i);
                if (!json_object_is_type(item, json_type_string)) throw std::runtime_error("name must be a string");
                std::string value = json_object_get_string(item);
                if (!value.empty() && fold(value) != "unknown" && std::find(candidates.begin(), candidates.end(), value) == candidates.end()) candidates.push_back(value);
            }
        }
        static const std::set<std::string> generic = {"application", "client", "game", "install", "installer", "launcher", "setup", "start", "update", "updater"};
        if (software_id.empty()) for (const auto &name : candidates)
        {
            auto normalized = normalize(name);
            if (normalized.size() < 4 || generic.count(normalized)) continue;
            software_id = id("SELECT s.id FROM software s LEFT JOIN report_agg a ON a.software_id = s.id WHERE s.name = ? COLLATE NOCASE ORDER BY COALESCE(a.reports, 0) DESC LIMIT 1", name);
            if (!software_id.empty()) { level = "name"; break; }
        }
        if (software_id.empty())
        {
            auto rows = query("SELECT s.id, s.name, COALESCE(a.reports, 0) AS reports FROM software s LEFT JOIN report_agg a ON a.software_id = s.id WHERE s.source != 'protondb' OR a.reports >= 10 ORDER BY COALESCE(a.reports, 0) DESC");
            for (const auto &name : candidates)
            {
                auto normalized = normalize(name);
                if (normalized.size() < 6 || generic.count(normalized)) continue;
                double best = 0;
                for (auto *row : rows)
                {
                    auto candidate = normalize(field(row, "name"));
                    if (candidate.empty() || numbers(candidate) != numbers(normalized)) continue;
                    double coverage = static_cast<double>(std::min(candidate.size(), normalized.size())) / std::max(candidate.size(), normalized.size());
                    if (coverage < 0.65) continue;
                    double score = ratio(normalized, candidate);
                    if (score >= 0.8 && score > best)
                    {
                        json_object *value = nullptr; json_object_object_get_ex(row, "id", &value);
                        software_id = json_object_get_string(value); best = score; level = "fuzzy";
                    }
                }
                if (!software_id.empty()) break;
            }
            for (auto *row : rows) json_object_put(row);
        }
        if (software_id.empty()) return nullptr;
        auto software = query("SELECT s.name, s.steam_appid, s.trick_name, s.source, COALESCE(a.reports, 0) AS reports, COALESCE(a.verdict_yes, 0) AS verdict_yes, COALESCE(a.verdict_no, 0) AS verdict_no, COALESCE(a.tinkered, 0) AS tinkered, a.tier FROM software s LEFT JOIN report_agg a ON a.software_id = s.id WHERE s.id = ?", software_id);
        if (software.empty()) return nullptr;
        auto tweaks = query("SELECT kind, value, evidence FROM tweak WHERE software_id = ? ORDER BY evidence DESC", software_id);
        auto *result = json_object_new_object(), *array = json_object_new_array();
        json_object_object_add(result, "match", json_object_new_string(level.c_str()));
        json_object_object_add(result, "software", software[0]);
        for (auto *row : tweaks) json_object_array_add(array, row);
        json_object_object_add(result, "tweaks", array);
        return result;
    }
};

static json_object *member(json_object *object, const char *name)
{
    json_object *value = nullptr;
    if (object) json_object_object_get_ex(object, name, &value);
    return value;
}

static void copy(json_object *destination, const char *key, json_object *value)
{
    json_object_object_add(destination, key, json_object_get(value));
}

static void text(json_object *destination, const char *key, const std::string &value)
{
    json_object_object_add(destination, key, json_object_new_string(value.c_str()));
}

static json_object *hint(json_object *value, int64_t evidence, const std::string &reason = "")
{
    auto *result = json_object_new_object();
    copy(result, "value", value);
    json_object_object_add(result, "evidence", json_object_new_int64(evidence));
    if (!reason.empty()) text(result, "reason", reason);
    return result;
}

static std::vector<std::string> split(const std::string &value, char separator)
{
    std::vector<std::string> result;
    size_t start = 0, end;
    while ((end = value.find(separator, start)) != std::string::npos) { result.push_back(value.substr(start, end-start)); start = end+1; }
    result.push_back(value.substr(start)); return result;
}

static std::string trim_quotes(std::string value)
{
    auto quote = [](char ch) { return ch == '\'' || ch == '"'; };
    while (!value.empty() && quote(value.front())) value.erase(0, 1);
    while (!value.empty() && quote(value.back())) value.pop_back();
    return value;
}

static json_object *plan(database &db, json_object *request)
{
    auto *hit = member(request, "hit"), *constants = member(request, "constants");
    auto *software = member(hit, "software"), *tweaks = member(hit, "tweaks");
    if (!software || !json_object_is_type(software, json_type_object) || !tweaks || !json_object_is_type(tweaks, json_type_array) || !constants)
        throw std::runtime_error("plan requires software, tweaks and constants");
    auto *result = json_object_new_object(), *parameters = json_object_new_object(), *environment = json_object_new_object();
    auto *overrides = json_object_new_object(), *arguments = json_object_new_array(), *dependencies = json_object_new_array(), *notes = json_object_new_array(), *credits = json_object_new_array();
    copy(result, "match", member(hit, "match")); copy(result, "name", member(software, "name"));
    json_object_object_add(result, "parameters", parameters); json_object_object_add(result, "env", environment);
    json_object_object_add(result, "dll_overrides", overrides); json_object_object_add(result, "args", arguments);
    json_object_object_add(result, "dependencies", dependencies); json_object_object_add(result, "notes", notes); json_object_object_add(result, "attributions", credits);
    std::set<std::string> attributed;
    auto credit = [&](const std::string &name)
    {
        if (attributed.insert(name).second) json_object_array_add(credits, json_object_get(member(member(constants, "sources"), name.c_str())));
    };
    auto note = [&](const std::string &value) { json_object_array_add(notes, json_object_new_string(value.c_str())); };
    auto dependency = [&](const std::string &name, int64_t evidence, const std::string &reason)
    {
        auto *item = json_object_new_object(); text(item, "name", name); text(item, "reason", reason);
        json_object_object_add(item, "evidence", json_object_new_int64(evidence)); json_object_array_add(dependencies, item);
    };
    auto mode = [&](const std::string &value)
    {
        auto *found = member(member(constants, "override_modes"), value.c_str());
        return found ? std::string(json_object_get_string(found)) : value;
    };
    const std::regex dll_name("^[A-Za-z0-9_.-]+$"), env_name("^[A-Z_][A-Z0-9_]*$"), env_value("^[A-Za-z0-9_.,:+/@% -]*$"), argument("^--?[A-Za-z0-9][A-Za-z0-9._:+/@,-]*(?:=[A-Za-z0-9._:+/@,-]+)?$");
    auto override = [&](const std::string &dll, const std::string &value, int64_t evidence)
    {
        if (!std::regex_match(dll, dll_name) || member(overrides, dll.c_str())) return;
        auto *string = json_object_new_string(value.c_str());
        json_object_object_add(overrides, dll.c_str(), hint(string, evidence)); json_object_put(string);
    };
    bool known = field(software, "source") == "winetricks";
    if (known)
    {
        text(result, "source", "winetricks"); credit("winetricks");
        for (const char *key : {"steam_appid", "tier"}) json_object_object_add(result, key, nullptr);
        for (const char *key : {"reports", "verdict_yes", "verdict_no"}) json_object_object_add(result, key, json_object_new_int(0));
        auto *verb = db.trick(field(software, "trick_name"));
        auto *items = json_tokener_parse(field(verb, "overrides_json").c_str());
        if (items && json_object_is_type(items, json_type_array)) for (size_t i = 0; i < json_object_array_length(items); i++)
        {
            auto *item = json_object_array_get_idx(items, i);
            auto *mapped = member(member(constants, "override_modes"), field(item, "mode").c_str());
            if (!mapped) continue;
            auto *dlls = member(item, "dlls");
            if (!dlls || !json_object_is_type(dlls, json_type_array)) continue;
            for (size_t j = 0; j < json_object_array_length(dlls); j++)
            {
                std::string dll = json_object_get_string(json_object_array_get_idx(dlls, j));
                if (std::regex_match(dll, dll_name)) override(fold(dll), json_object_get_string(mapped), 0);
            }
        }
        if (items) json_object_put(items);
        auto dep = field(verb, "bottles_dep");
        if (!dep.empty()) { dependency(dep, 0, "winetricks " + field(verb, "name") + " maps to this dependency"); credit("bottles_dependencies"); }
        note("Known application: " + field(software, "name") + " (winetricks verb '" + field(software, "trick_name") + "')");
        if (!field(verb, "winver").empty()) note("winetricks sets Windows version to " + field(verb, "winver") + " for it");
        if (verb) json_object_put(verb);
        return result;
    }
    text(result, "source", "protondb"); credit("protondb");
    for (const char *key : {"steam_appid", "tier", "reports", "verdict_yes", "verdict_no"}) copy(result, key, member(software, key));
    int64_t reports = std::max<int64_t>(json_object_get_int64(member(software, "reports")), 1), threshold = std::max<int64_t>(3, static_cast<int64_t>(reports * 0.02));
    auto propose = [&](json_object *mapping, int64_t evidence)
    {
        if (!mapping || !json_object_is_type(mapping, json_type_array) || json_object_array_length(mapping) != 3) return false;
        const char *key = json_object_get_string(json_object_array_get_idx(mapping, 0));
        auto *current = member(parameters, key);
        if (!current || evidence > json_object_get_int64(member(current, "evidence")))
            json_object_object_add(parameters, key, hint(json_object_array_get_idx(mapping, 1), evidence, json_object_get_string(json_object_array_get_idx(mapping, 2))));
        return true;
    };
    std::set<std::string> dependency_names;
    bool ge_note = false;
    for (size_t i = 0; i < json_object_array_length(tweaks); i++)
    {
        auto *item = json_object_array_get_idx(tweaks, i);
        std::string kind = field(item, "kind"), value = field(item, "value");
        int64_t evidence = json_object_get_int64(member(item, "evidence"));
        if (evidence < threshold) continue;
        if (kind == "launch_flag" && propose(member(member(constants, "launch_flags"), value.c_str()), evidence)) continue;
        size_t equal = value.find('=');
        if (kind == "launch_token" && equal != std::string::npos)
        {
            auto name = value.substr(0, equal), target = trim_quotes(value.substr(equal+1));
            auto *mapping = member(member(constants, "proton_env"), name.c_str());
            if (mapping && (fold(target) == "1" || fold(target) == "true")) { propose(mapping, evidence); continue; }
            if (name == "WINEDLLOVERRIDES")
            {
                target.erase(std::remove(target.begin(), target.end(), '\\'), target.end());
                for (const auto &pair : split(target, ';'))
                {
                    auto delimiter = pair.find('='); if (delimiter == std::string::npos) continue;
                    auto selected = mode(pair.substr(delimiter+1));
                    if (selected != "n" && selected != "b" && selected != "n,b" && selected != "b,n" && selected != "d") continue;
                    for (const auto &dll : split(pair.substr(0, delimiter), ',')) override(fold(trim_quotes(dll)), selected, evidence);
                }
                continue;
            }
            bool allowed = name == "PULSE_LATENCY_MSEC" || name == "STAGING_SHARED_MEMORY" || name.rfind("DXVK_", 0) == 0 || name.rfind("VKD3D_", 0) == 0 || name.rfind("WINE_", 0) == 0;
            if (allowed && name != "WINEARCH" && name != "WINEPREFIX" && target.size() <= 64 && std::regex_match(name, env_name) && std::regex_match(target, env_value) && !member(environment, name.c_str()))
            {
                auto *string = json_object_new_string(target.c_str()); json_object_object_add(environment, name.c_str(), hint(string, evidence)); json_object_put(string);
            }
            continue;
        }
        if (kind == "launch_token")
        {
            if (json_object_array_length(arguments) < 3 && std::regex_match(value, argument))
            { auto *string = json_object_new_string(value.c_str()); json_object_array_add(arguments, hint(string, evidence)); json_object_put(string); }
            continue;
        }
        if (kind == "customization" && value == "mediaFoundation") { note("Community reports needing a Media Foundation workaround (x" + std::to_string(evidence) + ")"); continue; }
        if (kind == "custom_proton" && value.rfind("GE-Proton", 0) == 0)
        {
            if (!ge_note) note("Community favors GE-Proton builds; Soda or Caffe is the closest Bottles runner (x" + std::to_string(evidence) + ")");
            ge_note = true; continue;
        }
        if (kind != "note_verb") continue;
        auto *verb = db.trick(value);
        if (!verb) continue;
        credit("winetricks");
        auto dep = field(verb, "bottles_dep");
        if (!dep.empty())
        {
            if (dependency_names.insert(dep).second) dependency(dep, evidence, "winetricks " + value + " mentioned in reports");
            credit("bottles_dependencies");
        }
        else note("Reports mention winetricks verb '" + value + "' (x" + std::to_string(evidence) + ")");
        json_object_put(verb);
    }
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fputs("usage: eagle-intel DATABASE < REQUEST\n", stderr); return 2; }
    std::string input;
    char buffer[4096];
    while (size_t count = fread(buffer, 1, sizeof(buffer), stdin))
    {
        input.append(buffer, count);
        if (input.size() > 1024*1024) { fputs("request exceeds size limit\n", stderr); return 1; }
    }
    auto *parser = json_tokener_new();
    json_object *request = json_tokener_parse_ex(parser, input.data(), input.size());
    bool valid = json_tokener_get_error(parser) == json_tokener_success;
    size_t consumed = json_tokener_get_parse_end(parser);
    json_tokener_free(parser);
    valid = valid && input.find_first_not_of(" \t\r\n", consumed) == std::string::npos;
    if (!valid || !request || !json_object_is_type(request, json_type_object)) { if (request) json_object_put(request); fputs("invalid request\n", stderr); return 1; }
    try
    {
        database db(argv[1]);
        auto *result = field(request, "operation") == "status" ? db.status() : field(request, "operation") == "plan" ? plan(db, request) : db.lookup(request);
        puts(result ? json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN) : "null");
        if (result) json_object_put(result);
        json_object_put(request); return 0;
    }
    catch (const std::exception &error) { json_object_put(request); fprintf(stderr, "%s\n", error.what()); return 1; }
}
