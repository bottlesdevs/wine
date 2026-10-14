#include <json-c/json.h>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <map>
#include <algorithm>
#include <vector>
#include <set>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <functional>
#include <ctime>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <glib.h>

static json_object *member(json_object *object, const char *name)
{
    json_object *value = nullptr;
    json_object_object_get_ex(object, name, &value);
    return value;
}

static std::string text(json_object *object, const char *name)
{
    auto *value = member(object, name);
    if (!value || !json_object_is_type(value, json_type_string)) throw std::runtime_error("expected string field");
    return json_object_get_string(value);
}

static std::string count(json_object *object)
{
    auto *value = member(object, "evidence");
    if (!value || !json_object_is_type(value, json_type_int)) throw std::runtime_error("expected evidence count");
    return std::to_string(json_object_get_int64(value));
}

static void string(json_object *object, const char *name, const std::string &value)
{
    json_object_object_add(object, name, json_object_new_string_len(value.data(), value.size()));
}

static json_object *suggestion(const std::string &key, json_object *value, const std::string &label, bool optional)
{
    auto *result = json_object_new_object();
    string(result, "key", key);
    json_object_object_add(result, "value", json_object_get(value));
    string(result, "label", label);
    if (optional) json_object_object_add(result, "apply", json_object_new_boolean(false));
    return result;
}

static json_object *merge(json_object *request)
{
    auto *suggestions = member(request, "suggestions"), *plan = member(request, "intel");
    if (!suggestions || !json_object_is_type(suggestions, json_type_array)) throw std::runtime_error("suggestions must be an array");
    if (!plan) return json_object_get(suggestions);
    if (!json_object_is_type(plan, json_type_object)) throw std::runtime_error("intel plan must be an object");
    for (const char *name : {"parameters", "env", "dll_overrides"})
        if (!json_object_is_type(member(plan, name), json_type_object)) throw std::runtime_error("intel mappings are missing");
    for (const char *name : {"dependencies", "args"})
        if (!json_object_is_type(member(plan, name), json_type_array)) throw std::runtime_error("intel arrays are missing");
    std::map<std::string, json_object *> existing;
    for (size_t i = 0; i < json_object_array_length(suggestions); i++)
    {
        auto *item = json_object_array_get_idx(suggestions, i);
        existing[text(item, "key")] = item;
    }
    json_object_object_foreach(member(plan, "parameters"), key, info)
    {
        std::string evidence = text(info, "reason") + " (x" + count(info) + ")";
        auto found = existing.find(key);
        if (found != existing.end())
        {
            auto *item = found->second;
            string(item, "label", json_object_equal(member(item, "value"), member(info, "value")) ? text(item, "label") + " [" + evidence + "]" : evidence);
            json_object_object_add(item, "value", json_object_get(member(info, "value")));
            json_object_object_add(item, "apply", json_object_new_boolean(false));
        }
        else
        {
            auto *item = suggestion(key, member(info, "value"), evidence, true);
            json_object_array_add(suggestions, item); existing[key] = item;
        }
    }
    auto *dependencies = member(plan, "dependencies");
    for (size_t i = 0; i < json_object_array_length(dependencies); i++)
    {
        auto *info = json_object_array_get_idx(dependencies, i);
        auto name = text(info, "name"), key = "dep_" + name;
        if (existing.count(key)) continue;
        auto *value = json_object_new_boolean(false);
        auto *item = suggestion(key, value, name + " (" + text(info, "reason") + ", x" + count(info) + ")", false);
        json_object_put(value);
        json_object_array_add(suggestions, item); existing[key] = item;
    }
    for (const char *mapping : {"env", "dll_overrides"})
    {
        json_object_object_foreach(member(plan, mapping), name, info)
        {
            bool environment = std::string(mapping) == "env";
            auto value = text(info, "value");
            auto key = std::string(environment ? "intel_env:" : "intel_dll:") + name;
            auto label = std::string(environment ? "Set " : "Override ") + name + "=" + value + " (community evidence x" + count(info) + ")";
            json_object_array_add(suggestions, suggestion(key, member(info, "value"), label, true));
        }
    }
    auto *arguments = member(plan, "args");
    for (size_t i = 0; i < json_object_array_length(arguments); i++)
    {
        auto *info = json_object_array_get_idx(arguments, i);
        auto value = text(info, "value");
        json_object_array_add(suggestions, suggestion("intel_arg:" + value, member(info, "value"), "Add launch argument " + value + " (community evidence x" + count(info) + ")", true));
    }
    return json_object_get(suggestions);
}

static std::string representation(json_object *value)
{
    if (!value) return "None";
    if (json_object_is_type(value, json_type_string))
    {
        std::string raw = json_object_get_string(value), result;
        char quote = raw.find('\'') != std::string::npos && raw.find('"') == std::string::npos ? '"' : '\'';
        result += quote;
        for (unsigned char ch : raw)
        {
            if (ch == quote || ch == '\\') { result += '\\'; result += ch; }
            else if (ch == '\n') result += "\\n";
            else if (ch == '\r') result += "\\r";
            else if (ch == '\t') result += "\\t";
            else if (ch < 32 || ch == 127) { char encoded[5]; snprintf(encoded, sizeof(encoded), "\\x%02x", ch); result += encoded; }
            else result += ch;
        }
        return result + quote;
    }
    if (json_object_is_type(value, json_type_boolean)) return json_object_get_boolean(value) ? "True" : "False";
    if (json_object_is_type(value, json_type_array))
    {
        std::string result = "[";
        for (size_t i = 0; i < json_object_array_length(value); i++)
        { if (i) result += ", "; result += representation(json_object_array_get_idx(value, i)); }
        return result + "]";
    }
    if (json_object_is_type(value, json_type_object))
    {
        std::string result = "{";
        json_object_object_foreach(value, key, item)
        {
            if (result.size() > 1) result += ", ";
            auto *name = json_object_new_string(key);
            result += representation(name) + ": " + representation(item);
            json_object_put(name);
        }
        return result + "}";
    }
    return json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
}

static json_object *recommend(json_object *request)
{
    auto *insights = member(request, "details"), *metadata = member(request, "metadata");
    if (!json_object_is_type(insights, json_type_object) || !json_object_is_type(metadata, json_type_object)) throw std::runtime_error("analysis details and metadata are required");
    std::map<std::string, std::vector<std::string>> flat;
    auto *frameworks = json_object_new_array(), *suggestions = json_object_new_array(), *messages = json_object_new_array();
    json_object_object_foreach(insights, category, items)
    {
        if (!json_object_is_type(items, json_type_array)) throw std::runtime_error("analysis categories must be arrays");
        for (size_t i = 0; i < json_object_array_length(items); i++)
        {
            auto *item = json_object_array_get_idx(items, i);
            bool object = json_object_is_type(item, json_type_object);
            if (!object && !json_object_is_type(item, json_type_string)) throw std::runtime_error("invalid analysis item");
            auto name = object ? text(item, "name") : std::string(json_object_get_string(item));
            flat[category].push_back(name);
            auto line = std::string(category) + ": " + (object ? representation(item) : name);
            json_object_array_add(frameworks, json_object_new_string(line.c_str()));
        }
    }
    auto has = [&](const char *category, const char *name) {
        const auto &items = flat[category];
        return std::find(items.begin(), items.end(), name) != items.end();
    };
    auto add = [&](const char *key, json_object *value, const std::string &label) {
        json_object_array_add(suggestions, suggestion(key, value, label, false)); json_object_put(value);
    };
    auto boolean = [&](const char *key, bool value, const std::string &label) { add(key, json_object_new_boolean(value), label); };
    auto message = [&](const char *name, const char *description, const char *severity, const std::string &context) {
        auto *item = json_object_new_object(), *contexts = json_object_new_array();
        string(item, "name", name); string(item, "description", description); string(item, "severity", severity);
        json_object_array_add(contexts, json_object_new_string(context.c_str()));
        json_object_object_add(item, "context", contexts); json_object_array_add(messages, item);
    };
    bool dx12 = false, dx11 = false, dx_engine = false, dx12_engine = false;
    for (const auto &name : flat["Graphics"])
    {
        if (name.find("DirectX") == std::string::npos && name.find("D3D") == std::string::npos && name.find("DXGI") == std::string::npos) continue;
        dx12 |= name.find("12") != std::string::npos;
        dx11 |= name.find("11") != std::string::npos || name.find('9') != std::string::npos || name.find("10") != std::string::npos || name.find("DXGI") != std::string::npos;
    }
    for (const char *name : {"Unity", "Unity IL2CPP", "Unreal", "Godot", "CryEngine", "REDengine", "Source", "RPG Maker"}) dx_engine |= has("Engines", name);
    dx12_engine = has("Engines", "Unreal") || has("Engines", "REDengine");
    bool vulkan = has("Graphics", "Vulkan"), physx = has("Physics", "PhysX");
    if (dx12 || dx12_engine) boolean("vkd3d", true, "Enable VKD3D (DX12)");
    if (dx11 || (dx_engine && !vulkan)) boolean("dxvk", true, "Enable DXVK (DX9-11)");
    if (vulkan && !dx_engine) boolean("dxvk", false, "DXVK not needed (native Vulkan)");
    if (has("Graphics", "NVAPI")) boolean("dxvk_nvapi", true, "Enable DXVK-NVAPI");
    if (has("Upscaling", "DLSS") || has("Upscaling", "DLSS 3 Frame Gen")) boolean("dxvk_nvapi", true, "Enable DXVK-NVAPI (for DLSS)");
    if (has("Upscaling", "AMD FSR") || has("Upscaling", "AMD FSR 2")) boolean("fsr", true, "Enable FSR (native support detected)");
    if (!flat["Engines"].empty() || !flat["Graphics"].empty())
    {
        boolean("gamemode", true, "Enable GameMode"); boolean("discrete_gpu", true, "Use discrete GPU");
        add("sync", json_object_new_string("esync"), "Esync (threading)");
    }
    if (dx11 || vulkan || physx) boolean("latencyflex", physx, "LatencyFlex (input lag)");
    std::set<std::string> runtimes, vcpp;
    for (const auto &name : flat["Runtimes"])
    {
        if (name.find(".NET") != std::string::npos) runtimes.insert(name);
        if (name.find("VC++") != std::string::npos) vcpp.insert(name);
    }
    if (json_object_get_boolean(member(request, "is_net")) && runtimes.empty()) runtimes.insert(".NET Framework");
    bool mono = has("Runtimes", "Mono");
    if (mono && !runtimes.empty()) boolean("dep_mono", false, "Wine Mono (Recommended first)");
    for (const auto &name : runtimes) boolean("dep_dotnet", false, name + (mono ? " (Try Mono first)" : ""));
    if (mono && runtimes.empty()) boolean("dep_mono", false, "Wine Mono");
    if (!vcpp.empty())
    {
        std::string names;
        for (const auto &name : vcpp) { if (!names.empty()) names += ", "; names += name; }
        boolean("dep_vcredist", false, "Visual C++ (" + names + ")");
    }
    if (!json_object_get_boolean(member(request, "dpi_aware"))) boolean("virtual_desktop", false, "Virtual Desktop (DPI)");
    auto *shipping = member(request, "ue_shipping_exe");
    if (shipping && json_object_is_type(shipping, json_type_string) && json_object_get_string_len(shipping))
        message("Unreal Engine Bootstrapper", "This is the Unreal Engine launcher, not the game binary. It runs a VC++ prerequisite check that often fails in Wine even when the runtime is correctly installed, causing a misleading error dialog. Add the shipping binary directly to avoid this.", "high", json_object_get_string(shipping));
    if (has("Warning", "UWP/Modern API")) message("UWP/Modern App", "Set Windows Version to 'Windows 10' or '11' and extract 'WinMetadata' to system32.", "high", "Detected Modern Windows API usage");
    if (has("Frameworks", "WPF")) message("WPF Optimization", "Use a runner with 'ChildWindow' patches (e.g. Soda, Wine-GE-Custom, Proton-GE).", "info", "Detected WPF (Windows Presentation Foundation)");
    if (json_object_get_boolean(member(metadata, "is_packed"))) message("Packed Binary", "Analysis might be limited due to packing.", "info", "Packed with " + text(metadata, "packer"));
    if (!flat["Protection"].empty())
    {
        std::string names;
        for (const auto &name : flat["Protection"]) { if (!names.empty()) names += ", "; names += name; }
        message("Protection Software", "This might cause compatibility or performance issues.", "high", "Detected: " + names);
    }
    if (has("Upscaling", "Intel XeSS")) message("Intel XeSS", "You might need to install the XeSS runtime manually.", "info", "Detected XeSS libraries");
    auto *merging = json_object_new_object();
    json_object_object_add(merging, "suggestions", suggestions);
    json_object_object_add(merging, "intel", json_object_get(member(request, "intel")));
    auto *merged = merge(merging);
    json_object_put(merging);
    auto *result = json_object_new_object();
    json_object_object_add(result, "suggestions", merged); json_object_object_add(result, "messages", messages); json_object_object_add(result, "frameworks", frameworks);
    return result;
}

static json_object *asar(json_object *request)
{
    namespace fs = std::filesystem;
    fs::path input = text(request, "path"), output = text(request, "output");
    if (!output.is_absolute() || fs::is_symlink(output) || !fs::is_directory(output) || !fs::is_empty(output)) throw std::runtime_error("ASAR output must be an empty private directory");
    struct stat status;
    if (stat(output.c_str(), &status) || status.st_uid != getuid() || (status.st_mode & 077)) throw std::runtime_error("ASAR output directory is not private");
    std::ifstream file(input, std::ios::binary);
    if (!file) throw std::runtime_error("ASAR archive is unavailable");
    uint64_t length = fs::file_size(input);
    unsigned char bytes[16];
    if (!file.read(reinterpret_cast<char *>(bytes), sizeof(bytes))) throw std::runtime_error("truncated ASAR header");
    auto number = [&](size_t offset) { return uint32_t(bytes[offset]) | uint32_t(bytes[offset+1]) << 8 | uint32_t(bytes[offset+2]) << 16 | uint32_t(bytes[offset+3]) << 24; };
    uint32_t size = number(12), pickle = number(4);
    if (!size || size > 1024 * 1024 || uint64_t(size) + 16 > length) throw std::runtime_error("ASAR header exceeds archive bounds");
    uint64_t base = uint64_t(size) + 16;
    if (pickle)
    {
        if (number(0) != 4 || uint64_t(pickle) < uint64_t(size) + 8 || uint64_t(pickle) + 8 > length || pickle - size > 12) throw std::runtime_error("invalid ASAR pickle bounds");
        base = uint64_t(pickle) + 8;
    }
    std::string encoded(size, '\0');
    if (!file.read(encoded.data(), size)) throw std::runtime_error("truncated ASAR directory");
    for (size_t i = 0; i < encoded.size(); i++) if (encoded[i] == '\\')
    {
        size_t start = i;
        while (i < encoded.size() && encoded[i] == '\\') i++;
        if ((i - start) % 2 && encoded.compare(i, 5, "u0000") == 0)
            throw std::runtime_error("ASAR directory contains a null character");
    }
    auto *parser = json_tokener_new();
    auto *header = json_tokener_parse_ex(parser, encoded.data(), encoded.size());
    bool valid = json_tokener_get_error(parser) == json_tokener_success;
    size_t consumed = json_tokener_get_parse_end(parser);
    json_tokener_free(parser);
    if (!valid || encoded.find_first_not_of(" \t\r\n", consumed) != std::string::npos || !json_object_is_type(header, json_type_object))
    { if (header) json_object_put(header); throw std::runtime_error("invalid ASAR directory"); }
    auto *files = json_object_new_array();
    size_t entries = 0;
    uint64_t total = 0;
    std::function<void(json_object *, const fs::path &, unsigned)> walk = [&](json_object *directory, const fs::path &relative, unsigned depth) {
        if (depth > 32) throw std::runtime_error("ASAR directory nesting exceeds limit");
        auto *children = member(directory, "files");
        if (!json_object_is_type(children, json_type_object)) throw std::runtime_error("invalid ASAR file table");
        json_object_object_foreach(children, name, info)
        {
            if (++entries > 10000) throw std::runtime_error("ASAR entry count exceeds limit");
            std::string component(name);
            if (component.empty() || component == "." || component == ".." || component.find_first_of("/\\") != std::string::npos || fs::path(component).is_absolute()) throw std::runtime_error("invalid ASAR entry path");
            if (!json_object_is_type(info, json_type_object)) throw std::runtime_error("invalid ASAR entry");
            auto destination = output / relative / component;
            if (member(info, "files"))
            {
                fs::create_directories(destination); fs::permissions(destination, fs::perms::owner_all, fs::perm_options::replace);
                walk(info, relative / component, depth+1); continue;
            }
            if (!member(info, "offset") || !member(info, "size")) continue;
            auto extension = fs::path(component).extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) { return ch >= 'A' && ch <= 'Z' ? ch+32 : ch; });
            if (extension != ".js" && extension != ".json" && extension != ".node" && extension != ".html" && extension != ".htm") continue;
            auto *offset_value = member(info, "offset"), *size_value = member(info, "size");
            auto integer = [](json_object *value) {
                if (!json_object_is_type(value, json_type_string) && !json_object_is_type(value, json_type_int))
                    throw std::runtime_error("ASAR entry number must be an integer or decimal string");
                std::string encoded = json_object_get_string(value);
                if (encoded.empty() || encoded.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("invalid ASAR entry offset or size");
                size_t end;
                uint64_t result = std::stoull(encoded, &end);
                if (end != encoded.size()) throw std::runtime_error("invalid ASAR entry number");
                return result;
            };
            uint64_t offset = integer(offset_value), amount = integer(size_value);
            if (offset > length - base || amount > 64 * 1024 * 1024 || amount > length - base - offset || total + amount > 256 * 1024 * 1024) throw std::runtime_error("ASAR entry exceeds archive bounds");
            total += amount;
            fs::create_directories(destination.parent_path());
            std::ofstream extracted(destination, std::ios::binary);
            if (!extracted) throw std::runtime_error("ASAR output file cannot be created");
            fs::permissions(destination, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
            file.seekg(base + offset);
            char buffer[65536];
            for (uint64_t remaining = amount; remaining;)
            {
                size_t count = std::min<uint64_t>(remaining, sizeof(buffer));
                if (!file.read(buffer, count) || !extracted.write(buffer, count)) throw std::runtime_error("ASAR file copy failed");
                remaining -= count;
            }
            json_object_array_add(files, json_object_new_string(destination.c_str()));
        }
    };
    try { walk(header, {}, 0); }
    catch (...) { json_object_put(header); json_object_put(files); throw; }
    json_object_put(header);
    return files;
}

static std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return ch >= 'A' && ch <= 'Z' ? ch+32 : ch; });
    return value;
}

static std::string manifest_value(std::string value)
{
    value.erase(0, value.find_first_not_of(" \t\r\n"));
    value.erase(value.find_last_not_of(" \t\r\n") + 1);
    return lower(value);
}

struct manifest_element
{
    std::string name, text;
    std::map<std::string, std::string> namespaces;
};

struct manifest_info
{
    bool admin = false;
    int legacy_dpi = -1, modern_dpi = -1;
    std::vector<manifest_element> elements;
    bool dpi() const { return (modern_dpi >= 0 ? modern_dpi : legacy_dpi) > 0; }
};

static manifest_info inspect_manifest(const std::string &xml)
{
    manifest_info result;
    GMarkupParser parser = {
        [](GMarkupParseContext *, const char *element, const char **names, const char **values, void *data, GError **) {
            auto &info = *static_cast<manifest_info *>(data);
            info.elements.push_back({element, "", {}});
            auto &current = info.elements.back();
            for (size_t i = 0; names[i]; i++)
            {
                std::string name = names[i];
                if (name == "xmlns") current.namespaces[""] = values[i];
                else if (name.compare(0, 6, "xmlns:") == 0) current.namespaces[name.substr(6)] = values[i];
            }
            auto separator = current.name.find(':');
            auto prefix = separator == std::string::npos ? "" : current.name.substr(0, separator);
            if (separator != std::string::npos) current.name.erase(0, separator + 1);
            std::string uri;
            for (auto it = info.elements.rbegin(); it != info.elements.rend(); ++it)
                if (auto found = it->namespaces.find(prefix); found != it->namespaces.end()) { uri = found->second; break; }
            auto expected = current.name == "dpiAware" ? "http://schemas.microsoft.com/SMI/2005/WindowsSettings" :
                            current.name == "dpiAwareness" ? "http://schemas.microsoft.com/SMI/2016/WindowsSettings" :
                            current.name == "requestedExecutionLevel" ? "urn:schemas-microsoft-com:asm.v3" : "";
            if ((!uri.empty() || !prefix.empty()) && uri != expected) current.name.clear();
            if (current.name == "requestedExecutionLevel")
                for (size_t i = 0; names[i]; i++)
                    if (std::string(names[i]) == "level" && lower(values[i]) == "requireadministrator") info.admin = true;
        },
        [](GMarkupParseContext *, const char *, void *data, GError **) {
            auto &info = *static_cast<manifest_info *>(data);
            auto element = std::move(info.elements.back()); info.elements.pop_back();
            auto value = manifest_value(element.text);
            if (element.name == "dpiAware") info.legacy_dpi = value == "true" || value == "true/pm" || value == "per monitor";
            if (element.name != "dpiAwareness") return;
            info.modern_dpi = 0;
            size_t start = 0;
            while (start <= value.size())
            {
                size_t end = value.find(',', start);
                auto item = manifest_value(value.substr(start, end == std::string::npos ? end : end - start));
                if (item == "unaware") break;
                if (item == "system" || item == "permonitor" || item == "permonitorv2") { info.modern_dpi = 1; break; }
                if (end == std::string::npos) break;
                start = end + 1;
            }
        },
        [](GMarkupParseContext *, const char *text, gsize length, void *data, GError **) {
            auto &info = *static_cast<manifest_info *>(data);
            if (!info.elements.empty()) info.elements.back().text.append(text, length);
        },
        nullptr, nullptr
    };
    auto *context = g_markup_parse_context_new(&parser, G_MARKUP_TREAT_CDATA_AS_TEXT, &result, nullptr);
    GError *error = nullptr;
    size_t offset = xml.compare(0, 3, "\xef\xbb\xbf") == 0 ? 3 : 0;
    bool valid = g_markup_parse_context_parse(context, xml.data() + offset, xml.size() - offset, &error) && g_markup_parse_context_end_parse(context, &error);
    g_markup_parse_context_free(context); g_clear_error(&error);
    return valid ? result : manifest_info{};
}

static json_object *pe_insights(json_object *request)
{
    auto *structure = member(request, "structure"), *details = member(request, "details"), *metadata = member(request, "metadata");
    auto *compilers = member(request, "compilers"), *packers = member(request, "packers"), *mapping = member(request, "mapping");
    for (auto *object : {structure, details, metadata, compilers, packers, mapping})
        if (!json_object_is_type(object, json_type_object)) throw std::runtime_error("PE interpretation requires object fields");
    for (const char *name : {"rich_products", "sections", "manifests", "imports"})
        if (!json_object_is_type(member(structure, name), json_type_array)) throw std::runtime_error("PE interpretation requires structure arrays");
    auto *steps = json_object_new_array();
    auto step = [&](const std::string &value) { json_object_array_add(steps, json_object_new_string(value.c_str())); };
    auto flag = [&](const char *name, bool value) { json_object_object_add(metadata, name, json_object_new_boolean(value)); };
    auto insight = [&](const char *category, const std::string &name, const char *source) {
        auto *items = member(details, category);
        if (!json_object_is_type(items, json_type_array)) throw std::runtime_error("PE insight category is missing");
        for (size_t i = 0; i < json_object_array_length(items); i++)
        {
            auto *item = json_object_array_get_idx(items, i);
            if (json_object_is_type(item, json_type_string) ? name == json_object_get_string(item) : name == text(item, "name")) return false;
        }
        auto *item = json_object_new_object(); string(item, "name", name); string(item, "source", source); json_object_array_add(items, item); return true;
    };
    step("Detecting architecture...");
    int machine = json_object_get_int(member(structure, "machine"));
    std::string architecture = machine == 0x14c ? "x86 (32-bit)" : machine == 0x8664 ? "x86_64 (64-bit)" : machine == 0xaa64 ? "ARM64" : "Unknown";
    step("Architecture: " + architecture);
    if (machine == 0xaa64)
    {
        auto *warning = json_object_new_object(); string(warning, "name", "ARM64 binary"); string(warning, "description", "Requires an ARM64-capable Wine runner. This debugger supports x86 and x64."); string(warning, "severity", "warning"); string(warning, "source", "Main Executable");
        auto *items = member(details, "Warning");
        if (!json_object_is_type(items, json_type_array)) throw std::runtime_error("PE warning category is missing");
        json_object_array_add(items, warning); step("[!] ARM64 requires a matching Wine runner; native debugging is unavailable in this build");
    }
    step("Checking PE characteristics...");
    int characteristics = json_object_get_int(member(structure, "characteristics"));
    int dll = json_object_get_int(member(structure, "dll_characteristics"));
    flag("large_address_aware", characteristics & 0x20); flag("dep_enabled", dll & 0x100); flag("aslr_enabled", dll & 0x40); flag("is_debug", characteristics & 0x200);
    if ((characteristics & 0x20) && machine == 0x14c) step("[+] Large Address Aware (can use >2GB RAM)");
    step("Checking OS requirements...");
    std::map<std::string, std::string> systems = {{"5.1", "Windows XP"}, {"6.0", "Vista"}, {"6.1", "Windows 7"}, {"6.2", "Windows 8"}, {"6.3", "Windows 8.1"}, {"10.0", "Windows 10/11"}};
    auto os = text(structure, "min_os"), os_name = systems.count(os) ? systems[os] : "Windows " + os;
    step("Minimum OS: " + os_name);
    step("Reading build metadata...");
    time_t timestamp = json_object_get_int64(member(structure, "timestamp"));
    struct tm date;
    if (timestamp > 0 && timestamp < 2147483647 && localtime_r(&timestamp, &date) && date.tm_year > 90 && date.tm_year < 200)
    {
        char value[16]; strftime(value, sizeof(value), "%Y-%m-%d", &date); string(metadata, "build_date", value); step(std::string("Build date: ") + value);
    }
    step("Analysing Rich header...");
    auto *products = member(structure, "rich_products");
    for (size_t i = 0; i < json_object_array_length(products); i++)
    {
        auto key = std::to_string(json_object_get_int(json_object_array_get_idx(products, i)));
        if (member(compilers, key.c_str())) { auto compiler = text(compilers, key.c_str()); string(metadata, "compiler", compiler); step("Compiler: " + compiler); break; }
    }
    step("Scanning PE sections...");
    auto *sections = member(structure, "sections");
    for (size_t i = 0; i < json_object_array_length(sections); i++)
    {
        auto *entry = json_object_array_get_idx(sections, i);
        auto name = text(entry, "name");
        if (name.size() != static_cast<size_t>(json_object_get_string_len(member(entry, "name")))) continue;
        if (member(packers, name.c_str())) { auto packer = text(packers, name.c_str()); flag("is_packed", true); string(metadata, "packer", packer); step("[!] Packer detected: " + packer); break; }
    }
    step("Extracting version info...");
    auto *version = member(structure, "version");
    auto publisher = member(version, "CompanyName") ? text(version, "CompanyName") : "Unknown";
    auto product = member(version, "ProductName") ? text(version, "ProductName") : text(request, "basename");
    if (publisher.empty()) publisher = "Unknown";
    if (product.empty()) product = text(request, "basename");
    if (auto *tables = member(structure, "version_tables"))
    {
        if (!json_object_is_type(tables, json_type_array)) throw std::runtime_error("PE version tables must be an array");
        if (json_object_array_length(tables)) { publisher = "Unknown"; product = text(request, "basename"); }
        for (size_t i = 0; i < json_object_array_length(tables); i++)
        {
            auto *table = json_object_array_get_idx(tables, i);
            if (!json_object_is_type(table, json_type_object)) throw std::runtime_error("PE version table must be an object");
            if (member(table, "CompanyName") && !text(table, "CompanyName").empty()) publisher = text(table, "CompanyName");
            if (member(table, "ProductName") && !text(table, "ProductName").empty()) product = text(table, "ProductName");
        }
    }
    if (publisher != "Unknown") step("Publisher: " + publisher);
    step("Parsing application manifest...");
    bool admin = false, dpi = false;
    auto *manifests = member(structure, "manifests");
    for (size_t i = 0; i < json_object_array_length(manifests); i++)
    {
        auto *item = json_object_array_get_idx(manifests, i);
        if (!json_object_is_type(item, json_type_string)) throw std::runtime_error("PE manifest must be a string");
        auto manifest = inspect_manifest(json_object_get_string(item));
        if (manifest.admin) { admin = true; step("[!] Requires administrator"); }
        dpi = dpi || manifest.dpi();
    }
    step("Checking .NET CLR header...");
    bool managed = json_object_get_boolean(member(structure, "managed"));
    if (managed) step("[✓] .NET managed code detected");
    step("Analysing import table...");
    std::set<std::string> imports;
    auto *libraries = member(structure, "imports");
    for (size_t i = 0; i < json_object_array_length(libraries); i++) imports.insert(lower(text(json_object_array_get_idx(libraries, i), "name")));
    step("Found " + std::to_string(imports.size()) + " imported libraries"); step("Mapping dependencies...");
    for (const auto &library : imports) if (auto *mapped = member(mapping, library.c_str()))
    {
        if (!json_object_is_type(mapped, json_type_array) || json_object_array_length(mapped) != 2) throw std::runtime_error("invalid DLL mapping");
        std::string name = json_object_get_string(json_object_array_get_idx(mapped, 0)), category = json_object_get_string(json_object_array_get_idx(mapped, 1));
        if (insight(category.c_str(), name, "Imports")) step("[" + category + "] " + name + " (Import)");
    }
    if (managed) insight("Runtimes", imports.count("hostfxr.dll") || imports.count("coreclr.dll") ? ".NET Core/5+" : ".NET Framework", "CLR Header");
    auto *result = json_object_new_object();
    json_object_object_add(result, "details", json_object_get(details)); json_object_object_add(result, "metadata", json_object_get(metadata)); json_object_object_add(result, "steps", steps);
    string(result, "arch", architecture); string(result, "min_os", os_name); string(result, "publisher", publisher); string(result, "product_name", product);
    json_object_object_add(result, "admin", json_object_new_boolean(admin)); json_object_object_add(result, "dpi_aware", json_object_new_boolean(dpi)); json_object_object_add(result, "is_net", json_object_new_boolean(managed));
    return result;
}

static std::string capture_context(const std::string &hex)
{
    if (hex.size() % 2) return {};
    std::string bytes;
    auto digit = [](char ch) { return ch >= '0' && ch <= '9' ? ch-'0' : ch >= 'a' && ch <= 'f' ? ch-'a'+10 : ch >= 'A' && ch <= 'F' ? ch-'A'+10 : -1; };
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int high = digit(hex[i]), low = digit(hex[i+1]);
        if (high < 0 || low < 0) return {};
        bytes += char(high * 16 + low);
    }
    gsize read = 0, written = 0;
    GError *error = nullptr;
    char *converted = g_convert(bytes.data(), bytes.size(), "UTF-8", bytes.find('\0') == std::string::npos ? "UTF-8" : "UTF-16LE", &read, &written, &error);
    if (!converted || read != bytes.size()) { g_free(converted); if (error) g_error_free(error); return {}; }
    std::string clean(converted, written); g_free(converted);
    size_t start = 0, end = clean.size();
    auto space = [](gunichar ch) { return g_unichar_isspace(ch) || (ch >= 0x1c && ch <= 0x1f); };
    while (start < end && space(g_utf8_get_char(clean.data()+start))) start = g_utf8_next_char(clean.data()+start) - clean.data();
    while (end > start)
    {
        const char *previous = g_utf8_find_prev_char(clean.data()+start, clean.data()+end);
        if (!previous || !space(g_utf8_get_char(previous))) break;
        end = previous - clean.data();
    }
    clean = clean.substr(start, end-start);
    clean.erase(std::remove(clean.begin(), clean.end(), '\0'), clean.end());
    char *uppercase = g_utf8_strup(clean.data(), clean.size());
    std::string upper(uppercase); g_free(uppercase);
    if (g_utf8_strlen(clean.data(), clean.size()) <= 2 || upper == "HKEY_LOCAL_MACHINE" || upper == "HKEY_CURRENT_USER" || upper == "HKLM" || upper == "HKCU" || upper == "HKLM\\" || upper == "HKCU\\") return {};
    return clean;
}

static json_object *yara_insights(json_object *request)
{
    auto *details = member(request, "details"), *rows = member(request, "matches");
    if (!json_object_is_type(details, json_type_object) || !json_object_is_type(rows, json_type_array)) throw std::runtime_error("YARA details and matches are required");
    auto source = text(request, "source");
    auto *matches = json_object_new_array(), *steps = json_object_new_array();
    for (size_t i = 0; i < json_object_array_length(rows); i++)
    {
        auto *row = json_object_array_get_idx(rows, i), *meta = member(row, "meta"), *strings = member(row, "strings");
        if (!json_object_is_type(meta, json_type_object) || !json_object_is_type(strings, json_type_array)) throw std::runtime_error("invalid YARA match");
        auto rule = text(row, "rule");
        auto value = [&](const char *key, const std::string &fallback) { return member(meta, key) ? text(meta, key) : fallback; };
        auto category = value("category", "Unknown"), name = value("name", rule), severity = value("severity", "info");
        auto description = value("description", "");
        auto *items = member(details, category.c_str());
        if (!items) { items = json_object_new_array(); json_object_object_add(details, category.c_str(), items); }
        if (!json_object_is_type(items, json_type_array)) throw std::runtime_error("YARA insight category must be an array");
        bool exists = false;
        for (size_t j = 0; j < json_object_array_length(items); j++)
        {
            auto *item = json_object_array_get_idx(items, j);
            if (json_object_is_type(item, json_type_string)) exists |= name == json_object_get_string(item);
            else exists |= name == text(item, "name");
        }
        auto *context = json_object_new_array();
        std::set<std::string> captured;
        for (size_t j = 0; j < json_object_array_length(strings); j++)
        {
            auto *item = json_object_array_get_idx(strings, j);
            auto ident = text(item, "identifier");
            if (ident != "$capture" && ident.find("key") == std::string::npos && ident.find("reg") == std::string::npos && rule != "Node_System_Commands" && rule != "Node_Native_Module" && rule != "Node_Kernel_Driver" && rule != "Driver_Service") continue;
            auto clean = capture_context(text(item, "hex"));
            if (!clean.empty() && captured.insert(clean).second && json_object_array_length(context) < 20) json_object_array_add(context, json_object_new_string_len(clean.data(), clean.size()));
        }
        if (!exists)
        {
            auto *item = json_object_new_object(); string(item, "name", name);
            if (category == "Warning" || category == "Security") { string(item, "description", description); string(item, "severity", severity); }
            string(item, "source", source);
            json_object_object_add(item, "context", json_object_get(context)); json_object_array_add(items, item);
            auto step = (category == "Warning" || category == "Security" ? "[!] " : "[" + category + "] ") + name + " (" + source + ")";
            json_object_array_add(steps, json_object_new_string(step.c_str()));
        }
        json_object_put(context);
        auto *match = json_object_new_object(); string(match, "rule", rule); string(match, "category", category); string(match, "name", name); string(match, "severity", severity); string(match, "source", source);
        json_object_array_add(matches, match);
    }
    auto *result = json_object_new_object();
    json_object_object_add(result, "details", json_object_get(details)); json_object_object_add(result, "matches", matches); json_object_object_add(result, "steps", steps);
    return result;
}

static json_object *discover(json_object *request)
{
    namespace fs = std::filesystem;
    fs::path executable = fs::canonical(text(request, "path")), directory = executable.parent_path();
    auto basename = executable.filename().string(), stem = executable.stem().string();
    auto *details = member(request, "details");
    if (!json_object_is_type(details, json_type_object)) throw std::runtime_error("analysis details are required");
    for (const char *name : {"Runtimes", "Engines", "Frameworks", "Analysed Files"})
        if (!json_object_is_type(member(details, name), json_type_array)) throw std::runtime_error("analysis category is missing");
    auto *steps = json_object_new_array(), *neighbors = json_object_new_array();
    auto step = [&](const std::string &value) { json_object_array_add(steps, json_object_new_string(value.c_str())); };
    auto add = [&](const char *category, const std::string &name, const char *message) {
        auto *items = member(details, category);
        for (size_t i = 0; i < json_object_array_length(items); i++)
        {
            auto *item = json_object_array_get_idx(items, i);
            if (json_object_is_type(item, json_type_string) && name == json_object_get_string(item)) return;
        }
        json_object_array_add(items, json_object_new_string(name.c_str()));
        step(message);
    };
    auto analysed = [&](const std::string &name) { json_object_array_add(member(details, "Analysed Files"), json_object_new_string(name.c_str())); };
    for (const auto &location : {directory, directory / "bin"})
    {
        auto runtime = stem + ".runtimeconfig.json", dependencies = stem + ".deps.json";
        if (fs::exists(location / runtime) || fs::exists(location / dependencies))
        {
            analysed(fs::exists(location / runtime) ? runtime : dependencies);
            add("Runtimes", ".NET Core/5+", "[Runtimes] .NET Core/5+ (self-contained)"); break;
        }
    }
    std::string shipping;
    if (fs::exists(directory / "Engine") || fs::exists(directory / "../Engine/Binaries"))
    {
        add("Engines", "Unreal", "[Engines] Unreal Engine");
        if (fs::exists(directory / "Engine") && lower(basename).find("shipping") == std::string::npos && fs::file_size(executable) < 1048576)
        {
            step("[!] Unreal Engine bootstrapper detected - searching for shipping binary...");
            std::error_code error;
            for (fs::directory_iterator it(directory, error), end; !error && it != end; it.increment(error))
            {
                if (!it->is_directory(error)) continue;
                for (const char *architecture : {"Win64", "Win32"})
                {
                    auto binaries = it->path() / "Binaries" / architecture;
                    if (!fs::is_directory(binaries, error)) { error.clear(); continue; }
                    for (fs::directory_iterator binary(binaries, error), last; !error && binary != last; binary.increment(error))
                    {
                        auto name = binary->path().filename().string(), folded = lower(name);
                        auto suffix = "-" + lower(architecture) + "-shipping.exe";
                        std::error_code status;
                        if (folded.size() >= suffix.size() && folded.compare(folded.size()-suffix.size(), suffix.size(), suffix) == 0 && binary->is_regular_file(status))
                        { shipping = binary->path().string(); step("[Engines] Shipping binary found: " + name); break; }
                    }
                    if (!shipping.empty()) break;
                }
                if (!shipping.empty()) break;
            }
        }
    }
    if (fs::exists(directory / "renpy")) add("Engines", "Ren'Py", "[Engines] Ren'Py");
    if (fs::exists(directory / "www") || fs::exists(directory / "Game.rgss3a")) add("Engines", "RPG Maker", "[Engines] RPG Maker");
    if (fs::exists(directory / (stem + ".pck")))
    { analysed(stem + ".pck"); add("Engines", "Godot", "[Engines] Godot"); }
    std::string archive;
    if (fs::exists(directory / "resources/app.asar"))
    { archive = (directory / "resources/app.asar").string(); analysed("resources/app.asar"); add("Frameworks", "Electron", "[Frameworks] Electron"); }
    std::set<fs::path> excluded;
    auto *home = g_get_home_dir();
    if (home)
    {
        excluded.insert(fs::weakly_canonical(home));
        for (const char *name : {"Downloads", "Desktop", "Documents", "Templates"}) excluded.insert(fs::weakly_canonical(fs::path(home) / name));
    }
    for (auto type : {G_USER_DIRECTORY_DOWNLOAD, G_USER_DIRECTORY_DESKTOP, G_USER_DIRECTORY_DOCUMENTS, G_USER_DIRECTORY_TEMPLATES})
        if (auto *path = g_get_user_special_dir(type)) excluded.insert(fs::weakly_canonical(path));
    auto path = directory.string();
    bool safe = !excluded.count(directory) && !(path.find("/run/user/") != std::string::npos && path.find("/doc/") != std::string::npos);
    size_t entries = 0;
    std::error_code error;
    if (safe) for (fs::directory_iterator it(directory, error), end; !error && it != end; it.increment(error))
    {
        if (++entries > 65536) throw std::runtime_error("neighbor directory exceeds entry limit");
        if (lower(it->path().extension().string()) == ".dll") json_object_array_add(neighbors, json_object_new_string(it->path().c_str()));
    }
    auto plugins = directory / (stem + "_Data") / "Plugins";
    if (fs::is_directory(plugins, error))
    {
        std::function<void(const fs::path &, unsigned)> walk = [&](const fs::path &location, unsigned depth) {
            if (depth > 32) throw std::runtime_error("plugin directory exceeds traversal limit");
            std::vector<fs::directory_entry> children;
            std::error_code failure;
            for (fs::directory_iterator it(location, fs::directory_options::skip_permission_denied, failure), end; !failure && it != end; it.increment(failure))
            {
                if (++entries > 65536) throw std::runtime_error("plugin directory exceeds traversal limit");
                children.push_back(*it);
                if (it->path().extension() == ".dll") json_object_array_add(neighbors, json_object_new_string(it->path().c_str()));
            }
            for (const auto &child : children) if (child.is_directory(failure) && !child.is_symlink(failure)) walk(child.path(), depth+1);
        };
        walk(plugins, 0);
    }
    auto *result = json_object_new_object();
    json_object_object_add(result, "details", json_object_get(details));
    json_object_object_add(result, "steps", steps); json_object_object_add(result, "neighbors", neighbors);
    json_object_object_add(result, "neighbor_scan_allowed", json_object_new_boolean(safe));
    string(result, "asar", archive); string(result, "ue_shipping_exe", shipping);
    return result;
}

static bool steam_metadata(const std::filesystem::path &path, std::string &contents)
{
    int descriptor = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    struct stat status;
    if (descriptor < 0) return false;
    if (fstat(descriptor, &status) || !S_ISREG(status.st_mode))
    { close(descriptor); return false; }
    char buffer[4096];
    ssize_t size;
    do
    {
        size = read(descriptor, buffer, sizeof(buffer));
        if (size > 0) contents.append(buffer, size);
        if (contents.size() > 1024 * 1024)
        { close(descriptor); throw std::runtime_error("Steam metadata exceeds byte limit"); }
    } while (size > 0 || (size < 0 && errno == EINTR));
    close(descriptor);
    return size == 0;
}

static bool steam_digit(gunichar character)
{
    static const gunichar extra[][2] = {
        {0xb2, 0xb3}, {0xb9, 0xb9}, {0x1369, 0x1371}, {0x19da, 0x19da},
        {0x2070, 0x2070}, {0x2074, 0x2079}, {0x2080, 0x2089}, {0x2460, 0x2468},
        {0x2474, 0x247c}, {0x2488, 0x2490}, {0x24ea, 0x24ea}, {0x24f5, 0x24fd},
        {0x24ff, 0x24ff}, {0x2776, 0x277e}, {0x2780, 0x2788}, {0x278a, 0x2792},
        {0x10a40, 0x10a43}, {0x10e60, 0x10e68}, {0x11052, 0x1105a}, {0x1f100, 0x1f10a}
    };
    if (g_unichar_isdigit(character)) return true;
    for (const auto &range : extra) if (character >= range[0] && character <= range[1]) return true;
    return false;
}

static bool steam_space(gunichar character)
{
    return g_unichar_isspace(character) || (character >= 0x1c && character <= 0x1f);
}

static std::string steam_match(const std::string &contents, const char *pattern)
{
    auto *expression = g_regex_new(pattern, GRegexCompileFlags(0), GRegexMatchFlags(0), nullptr);
    if (!expression) throw std::runtime_error("invalid Steam metadata expression");
    GMatchInfo *matches = nullptr;
    bool found = g_regex_match_full(expression, contents.data(), contents.size(), 0, GRegexMatchFlags(0), &matches, nullptr);
    std::string result;
    if (found)
    {
        int begin, end;
        if (g_match_info_fetch_pos(matches, 1, &begin, &end) && begin >= 0) result = contents.substr(begin, end-begin);
    }
    if (matches) g_match_info_free(matches);
    g_regex_unref(expression);
    return result;
}

static std::string steam_appid(json_object *request)
{
    namespace fs = std::filesystem;
    auto input = text(request, "path");
    auto executable = (input.empty() ? fs::current_path() : fs::absolute(input)).lexically_normal();
    while (executable.filename().empty() && executable.parent_path() != executable) executable = executable.parent_path();
    auto directory = executable.parent_path();
    for (const auto &location : {directory, directory.parent_path()})
    {
        std::string contents;
        if (!steam_metadata(location / "steam_appid.txt", contents)) continue;
        const char *validated = contents.data(), *limit = validated + contents.size();
        while (validated < limit)
        {
            if (!*validated) { validated++; continue; }
            auto character = g_utf8_get_char_validated(validated, limit-validated);
            if (character == gunichar(-1) || character == gunichar(-2)) throw std::runtime_error("invalid UTF-8 in Steam AppID file");
            validated = g_utf8_next_char(validated);
        }
        const char *begin = contents.data(), *end = begin + contents.size();
        while (begin < end && steam_space(g_utf8_get_char(begin))) begin = g_utf8_next_char(begin);
        const char *last = begin;
        bool numeric = true;
        while (last < end && !steam_space(g_utf8_get_char(last)))
        { numeric = numeric && steam_digit(g_utf8_get_char(last)); last = g_utf8_next_char(last); }
        if (last != begin && numeric) return std::string(begin, last);
    }
    std::vector<fs::path> parts;
    for (const auto &part : directory) parts.push_back(part);
    fs::path steamapps;
    std::string installed;
    for (size_t i = 1; i + 1 < parts.size(); i++) if (parts[i] == "common" && parts[i-1] == "steamapps")
    {
        for (size_t j = 0; j < i; j++) steamapps /= parts[j];
        installed = parts[i+1].string();
        break;
    }
    if (steamapps.empty()) return "";
    auto *folded = g_utf8_casefold(installed.c_str(), -1);
    std::string installation = folded ? folded : installed;
    g_free(folded);
    size_t entries = 0;
    std::error_code error;
    for (fs::directory_iterator it(steamapps, error), end; !error && it != end; it.increment(error))
    {
        if (++entries > 65536) throw std::runtime_error("Steam directory exceeds entry limit");
        if (it->path().filename().string().rfind("appmanifest_", 0)) continue;
        std::string raw, contents;
        if (!steam_metadata(it->path(), raw)) return "";
        const char *position = raw.data(), *last = position + raw.size();
        while (position < last)
        {
            if (!*position) { contents.push_back(0); position++; continue; }
            auto character = g_utf8_get_char_validated(position, last-position);
            if (character == gunichar(-1) || character == gunichar(-2)) { position++; continue; }
            const char *next = g_utf8_next_char(position);
            contents.append(position, next); position = next;
        }
        auto name = steam_match(contents, "(*UCP)\"installdir\"[\\s\\x1c-\\x1f]+\"([^\"]+)\"");
        if (name.find('\0') != std::string::npos) continue;
        auto *candidate = g_utf8_casefold(name.c_str(), -1);
        bool same = candidate && installation == candidate;
        g_free(candidate);
        if (!same) continue;
        auto appid = steam_match(contents, "(*UCP)\"appid\"[\\s\\x1c-\\x1f]+\"(\\d+)\"");
        if (!appid.empty()) return appid;
    }
    return "";
}

static json_object *artifact_hashes(json_object *request)
{
    auto path = text(request, "path"), imports = text(request, "imports");
    auto *result = json_object_new_object();
    string(result, "sha256", ""); string(result, "imphash", "");
    if (!imports.empty())
    {
        auto *checksum = g_checksum_new(G_CHECKSUM_MD5);
        g_checksum_update(checksum, (const guchar *)imports.data(), imports.size());
        string(result, "imphash", g_checksum_get_string(checksum));
        g_checksum_free(checksum);
    }
    int descriptor = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    struct stat before, after;
    if (descriptor < 0) return result;
    if (fstat(descriptor, &before) || !S_ISREG(before.st_mode))
    { close(descriptor); return result; }
    auto *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    char buffer[65536];
    ssize_t size;
    do
    {
        size = read(descriptor, buffer, sizeof(buffer));
        if (size > 0) g_checksum_update(checksum, (const guchar *)buffer, size);
    } while (size > 0 || (size < 0 && errno == EINTR));
    if (!size && !fstat(descriptor, &after) && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec)
        string(result, "sha256", g_checksum_get_string(checksum));
    close(descriptor); g_checksum_free(checksum);
    return result;
}

int main(int argc, char **)
{
    if (argc != 1) { fputs("usage: eagle-analysis < REQUEST\n", stderr); return 2; }
    std::string input;
    char buffer[4096];
    while (size_t count = fread(buffer, 1, sizeof(buffer), stdin))
    {
        input.append(buffer, count);
        if (input.size() > 1024 * 1024) { fputs("request exceeds size limit\n", stderr); return 1; }
    }
    auto *parser = json_tokener_new();
    auto *request = json_tokener_parse_ex(parser, input.data(), input.size());
    bool valid = json_tokener_get_error(parser) == json_tokener_success;
    size_t consumed = json_tokener_get_parse_end(parser);
    json_tokener_free(parser);
    valid = valid && input.find_first_not_of(" \t\r\n", consumed) == std::string::npos;
    if (!valid || !json_object_is_type(request, json_type_object))
    { if (request) json_object_put(request); fputs("invalid request\n", stderr); return 1; }
    try
    {
        auto operation = text(request, "operation");
        if (operation != "merge" && operation != "recommend" && operation != "asar" && operation != "discover" && operation != "yara-insights" && operation != "pe-insights" && operation != "artifact-hashes" && operation != "steam-appid") throw std::runtime_error("unsupported analysis operation");
        auto *result = operation == "steam-appid" ? json_object_new_string(steam_appid(request).c_str()) : operation == "artifact-hashes" ? artifact_hashes(request) : operation == "merge" ? merge(request) : operation == "recommend" ? recommend(request) : operation == "asar" ? asar(request) : operation == "yara-insights" ? yara_insights(request) : operation == "pe-insights" ? pe_insights(request) : discover(request);
        puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
        json_object_put(result); json_object_put(request); return 0;
    }
    catch (const std::exception &error)
    { json_object_put(request); fprintf(stderr, "%s\n", error.what()); return 1; }
}
