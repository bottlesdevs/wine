#include <json-c/json.h>
#include <glib.h>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = std::unique_ptr<json_object, decltype(&json_object_put)>;

static volatile sig_atomic_t cancel_signal;
static void interrupt(int signal) { if (!cancel_signal) cancel_signal = signal; }

struct analysis_cancelled : std::runtime_error
{
    analysis_cancelled() : std::runtime_error("analysis cancelled") {}
};

static void check_cancelled() { if (cancel_signal) throw analysis_cancelled(); }

static json own(json_object *value) { return json(value, json_object_put); }
static json object() { return own(json_object_new_object()); }
static json_object *get(json_object *value, const char *key) { return json_object_object_get(value, key); }
static std::string text(json_object *value) { return value ? json_object_get_string(value) : ""; }
static void set(json_object *value, const char *key, json_object *item) { json_object_object_add(value, key, json_object_get(item)); }
static void string(json_object *value, const char *key, const std::string &item) { json_object_object_add(value, key, json_object_new_string_len(item.data(), item.size())); }
static std::string encode(json_object *value) { return json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN); }

static json parse(const std::string &input)
{
    auto *parser = json_tokener_new();
    auto result = own(json_tokener_parse_ex(parser, input.c_str(), input.size() + 1));
    bool valid = json_tokener_get_error(parser) == json_tokener_success;
    size_t consumed = json_tokener_get_parse_end(parser);
    json_tokener_free(parser);
    if (!valid || input.find_first_not_of(" \t\r\n", consumed) != std::string::npos) throw std::runtime_error("invalid helper JSON");
    return result;
}

static json file_json(const fs::path &path)
{
    check_cancelled();
    int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    struct stat info;
    if (descriptor < 0) throw std::runtime_error("analysis configuration is unavailable");
    if (fstat(descriptor, &info) || !S_ISREG(info.st_mode)) { close(descriptor); throw std::runtime_error("configuration must be a regular file"); }
    auto close_file = [](FILE *file) { fclose(file); };
    auto file = std::unique_ptr<FILE, decltype(close_file)>(fdopen(descriptor, "rb"), close_file);
    if (!file) { close(descriptor); throw std::runtime_error("cannot read analysis configuration"); }
    std::string data; char buffer[4096];
    while (size_t count = fread(buffer, 1, sizeof(buffer), file.get()))
    {
        data.append(buffer, count);
        if (data.size() > 1024 * 1024) throw std::runtime_error("analysis configuration exceeds limit");
    }
    check_cancelled();
    if (ferror(file.get())) throw std::runtime_error("cannot read analysis configuration");
    return parse(data);
}

struct extraction
{
    fs::path path;
    explicit extraction(const fs::path &base)
    {
        if (base.empty()) throw std::runtime_error("an extraction workspace is required");
        auto pattern = (fs::canonical(base) / "eagle-asar-XXXXXX").string();
        std::vector<char> value(pattern.begin(), pattern.end()); value.push_back(0);
        if (!mkdtemp(value.data())) throw std::runtime_error("cannot create extraction directory");
        path = value.data();
    }
    ~extraction() { std::error_code error; fs::remove_all(path, error); }
    extraction(const extraction &) = delete;
    extraction &operator=(const extraction &) = delete;
};

struct process
{
    int pipes[3][2] = {{-1, -1}, {-1, -1}, {-1, -1}};
    pid_t pid = 0;
    ~process()
    {
        if (pid > 0)
        {
            kill(-pid, SIGKILL); kill(pid, SIGKILL);
            while (waitpid(-pid, nullptr, 0) > 0 || errno == EINTR) {}
            while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
        }
        for (auto &pipe : pipes) for (int descriptor : pipe) if (descriptor >= 0) close(descriptor);
    }
    void close_fd(int &descriptor) { if (descriptor >= 0) close(descriptor); descriptor = -1; }
};

struct tool_failure : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

static std::string run_tool(const std::vector<std::string> &arguments, const std::string &input = "", unsigned timeout = 30)
{
    check_cancelled();
    process child;
    for (auto &pipe : child.pipes) if (pipe2(pipe, O_CLOEXEC)) throw std::runtime_error("cannot create helper pipes");
    std::vector<char *> argv;
    for (const auto &argument : arguments) argv.push_back(const_cast<char *>(argument.c_str()));
    argv.push_back(nullptr);
    child.pid = fork();
    if (child.pid < 0) throw std::runtime_error("cannot start analysis helper");
    if (!child.pid)
    {
        if (setpgid(0, 0)) _exit(127);
        if (dup2(child.pipes[0][0], STDIN_FILENO) < 0 || dup2(child.pipes[1][1], STDOUT_FILENO) < 0 || dup2(child.pipes[2][1], STDERR_FILENO) < 0) _exit(127);
        for (auto &pipe : child.pipes) for (int descriptor : pipe) close(descriptor);
        execv(argv[0], argv.data()); _exit(127);
    }
    if (setpgid(child.pid, child.pid) && errno != EACCES && errno != ESRCH) throw std::runtime_error("cannot isolate analysis helper");
    child.close_fd(child.pipes[0][0]); child.close_fd(child.pipes[1][1]); child.close_fd(child.pipes[2][1]);
    int &in = child.pipes[0][1], &out = child.pipes[1][0], &err = child.pipes[2][0];
    for (int descriptor : {in, out, err})
    {
        int flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) throw std::runtime_error("cannot configure helper pipes");
    }
    if (input.empty()) child.close_fd(in);
    size_t sent = 0;
    std::string output, errors;
    bool exited = false, succeeded = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    while (!exited || out >= 0 || err >= 0)
    {
        check_cancelled();
        if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("analysis helper timed out");
        pollfd descriptors[] = {{in, POLLOUT, 0}, {out, POLLIN, 0}, {err, POLLIN, 0}};
        if (poll(descriptors, 3, 100) < 0 && errno != EINTR) throw std::runtime_error("analysis helper poll failed");
        if (in >= 0 && descriptors[0].revents)
        {
            ssize_t count = write(in, input.data() + sent, input.size() - sent);
            if (count > 0) sent += count;
            else if (count < 0 && errno != EAGAIN && errno != EINTR) child.close_fd(in);
            if (sent == input.size()) child.close_fd(in);
        }
        for (unsigned index = 1; index <= 2; index++) if (descriptors[index].revents)
        {
            int &descriptor = index == 1 ? out : err;
            auto &result = index == 1 ? output : errors;
            char buffer[8192];
            while (descriptor >= 0)
            {
                check_cancelled();
                ssize_t count = read(descriptor, buffer, sizeof(buffer));
                if (count > 0) result.append(buffer, count);
                else if (!count) child.close_fd(descriptor);
                else if (errno == EAGAIN || errno == EINTR) break;
                else throw std::runtime_error("cannot read analysis helper output");
                if (result.size() > 16 * 1024 * 1024) throw std::runtime_error("analysis helper output exceeds limit");
            }
        }
        if (!exited)
        {
            siginfo_t status = {};
            if (waitid(P_PID, child.pid, &status, WEXITED | WNOHANG | WNOWAIT))
            { if (errno != EINTR) throw std::runtime_error("cannot wait for analysis helper"); }
            else if (status.si_pid == child.pid)
            {
                exited = true; succeeded = status.si_code == CLD_EXITED && !status.si_status;
                child.close_fd(in);
                // Keep the leader unreaped until its group has been stopped.
                kill(-child.pid, SIGKILL);
            }
        }
    }
    check_cancelled();
    if (!succeeded) throw tool_failure(errors.empty() ? "analysis helper failed" : errors);
    return output;
}

static json tool(const std::vector<std::string> &arguments, const std::string &input = "", unsigned timeout = 30)
{
    return parse(run_tool(arguments, input, timeout));
}

static std::string program(const char *name)
{
    gchar *path = g_find_program_in_path(name);
    std::string result = path ? path : ""; g_free(path); return result;
}

class analyzer
{
    fs::path native, target, rules, workspace;
    std::string extractor_python;
    size_t scan_limit = 50;
    std::vector<fs::path> databases;
    json config, details = object();

    void step(const std::string &message)
    {
        check_cancelled();
        auto event = object(); string(event.get(), "event", "step"); string(event.get(), "data", message);
        puts(encode(event.get()).c_str()); fflush(stdout);
    }
    void steps(json_object *result)
    {
        auto *items = get(result, "steps");
        for (size_t index = 0; index < json_object_array_length(items); index++) step(text(json_object_array_get_idx(items, index)));
    }
    json call(const char *operation, json request, unsigned timeout = 30)
    {
        string(request.get(), "operation", operation);
        return tool({(native / "eagle-analysis").string()}, encode(request.get()), timeout);
    }
    size_t scan(const fs::path &path, const std::string &source = "Main Executable")
    {
        try
        {
            if (!fs::is_regular_file(path)) throw std::runtime_error("scan target must be a regular file");
            auto rows = tool({(native / "eagle-yara").string(), rules.string(), path.string(), "30"}, "", 35);
            auto request = object(); set(request.get(), "matches", get(rows.get(), "matches")); set(request.get(), "details", details.get()); string(request.get(), "source", source);
            auto result = call("yara-insights", std::move(request));
            details = own(json_object_get(get(result.get(), "details"))); steps(result.get());
            return json_object_array_length(get(result.get(), "matches"));
        }
        catch (const analysis_cancelled &) { throw; }
        catch (const std::exception &error) { fprintf(stderr, "Eagle pattern scan failed: %s\n", error.what()); return 0; }
    }
    std::vector<fs::path> installer(const std::string &type, const fs::path &output)
    {
        std::vector<fs::path> files;
        try
        {
            step("Extracting " + type + " installer...");
            std::string extractor;
            for (const char *name : {"7z", "7za", "7zr"}) if ((extractor = program(name)) != "") break;
            bool extracted = false;
            if (!extractor.empty())
            {
                std::vector<std::string> arguments = {extractor, "x", "-y", "-o" + output.string(), target.string()};
                for (const char *filter : {"*.exe", "*.dll", "*.msi", "*.json", "*.xml", "*.config", "*.manifest", "*.ini", "*.js", "*.vdf", "*.reg"})
                { arguments.push_back(std::string("-i!") + filter); arguments.push_back(std::string("-i!**/") + filter); }
                try { run_tool(arguments, "", 120); extracted = true; }
                catch (const tool_failure &) {}
            }
            if (!extracted)
            {
                auto python = extractor_python.empty() ? program("python3") : extractor_python;
                if (python.empty()) throw std::runtime_error("no extraction tool available");
                // Keep the existing optional extractor without invoking the Python analyzer.
                run_tool({python, "-c", "import patoolib,sys; patoolib.extract_archive(sys.argv[1], outdir=sys.argv[2], verbosity=-1)", target.string(), output.string()}, "", 120);
            }
            for (const char *extension : {".exe", ".dll"})
            {
                std::function<void(const fs::path &, unsigned)> collect = [&](const fs::path &directory, unsigned depth) {
                    check_cancelled();
                    if (depth > 64 || files.size() > 100000) throw std::runtime_error("installer traversal exceeds limit");
                    std::vector<fs::directory_entry> entries;
                    for (const auto &entry : fs::directory_iterator(directory)) if (entry.path().filename().string().front() != '.') entries.push_back(entry);
                    for (const auto &entry : entries) if (entry.path().extension() == extension && entry.is_regular_file()) files.push_back(entry.path());
                    for (const auto &entry : entries) if (!entry.is_symlink() && entry.is_directory()) collect(entry.path(), depth + 1);
                };
                collect(output, 0);
            }
            step("Found " + std::to_string(files.size()) + " binaries in installer");
        }
        catch (const analysis_cancelled &) { throw; }
        catch (const std::exception &error)
        {
            fprintf(stderr, "Eagle extraction failed: %s\n", error.what());
            step("Extraction skipped (not supported)");
        }
        return files;
    }
    void scan_installer(const std::vector<fs::path> &files, bool record)
    {
        size_t count = std::min(scan_limit, files.size());
        for (size_t index = 0; index < count; index++)
        {
            if (!fs::exists(files[index])) continue;
            auto name = files[index].filename().string();
            if (record) json_object_array_add(get(details.get(), "Analysed Files"), json_object_new_string(name.c_str()));
            step("[" + std::to_string(index + 1) + "/" + std::to_string(count) + "] Scanning: " + name);
            scan(files[index], name);
        }
    }
    json intelligence(json_object *structure, const std::string &product)
    {
        for (const auto &database : databases)
        {
            auto request = object(); string(request.get(), "operation", "status");
            json status = own(nullptr);
            try { status = tool({(native / "eagle-intel").string(), database.string()}, encode(request.get())); }
            catch (const analysis_cancelled &) { throw; }
            catch (const std::exception &) { continue; }
            try
            {
                auto lookup = object();
                if (json_object_get_boolean(get(status.get(), "has_artifacts")))
                {
                    auto input = object(); string(input.get(), "path", target.string()); string(input.get(), "imports", text(get(structure, "imphash_material")));
                    auto hashes = call("artifact-hashes", std::move(input));
                    for (const char *key : {"sha256", "imphash"}) set(lookup.get(), key, get(hashes.get(), key));
                }
                auto input = object(); string(input.get(), "path", target.string());
                auto appid = call("steam-appid", std::move(input)); set(lookup.get(), "steam_appid", appid.get());
                string(lookup.get(), "product_name", product);
                auto names = own(json_object_new_array()); json_object_array_add(names.get(), json_object_new_string(target.stem().c_str())); set(lookup.get(), "names", names.get());
                auto hit = own(nullptr);
                try { hit = tool({(native / "eagle-intel").string(), database.string()}, encode(lookup.get())); }
                catch (const tool_failure &error)
                {
                    fprintf(stderr, "Eagle Intel lookup failed: %s\n", error.what());
                    step("No community intelligence match"); return own(nullptr);
                }
                if (!hit) { step("No community intelligence match"); return own(nullptr); }
                auto plan_request = object(); string(plan_request.get(), "operation", "plan"); set(plan_request.get(), "hit", hit.get()); set(plan_request.get(), "constants", get(config.get(), "intel"));
                auto plan = tool({(native / "eagle-intel").string(), database.string()}, encode(plan_request.get()));
                if (text(get(plan.get(), "source")) == "winetricks") step("Known application (" + text(get(plan.get(), "match")) + "): " + text(get(plan.get(), "name")));
                else step("Community match (" + text(get(plan.get(), "match")) + "): " + text(get(plan.get(), "name")) + ", tier " + text(get(plan.get(), "tier")) + ", " + text(get(plan.get(), "reports")) + " reports");
                return plan;
            }
            catch (const analysis_cancelled &) { throw; }
            catch (const std::exception &error) { fprintf(stderr, "Eagle Intel lookup failed: %s\n", error.what()); return own(nullptr); }
        }
        return own(nullptr);
    }
public:
    analyzer(const fs::path &executable, json_object *request) : native(executable.parent_path()), config(object())
    {
        auto *path = get(request, "target");
        if (!json_object_is_type(path, json_type_string)) throw std::runtime_error("target must be a path string");
        target = fs::canonical(text(path));
        if (!fs::is_regular_file(target)) throw std::runtime_error("target must be a regular file");
        auto *limit = get(request, "scan_limit");
        if (limit && (!json_object_is_type(limit, json_type_int) || json_object_get_int64(limit) < 1 || json_object_get_int64(limit) > 10000)) throw std::runtime_error("scan limit must be between 1 and 10000");
        if (limit) scan_limit = json_object_get_int64(limit);
        config = file_json(get(request, "config") ? fs::path(text(get(request, "config"))) : native.parent_path() / "analysis.json");
        for (const char *key : {"compilers", "packers", "mapping", "intel"})
            if (!json_object_is_type(get(config.get(), key), json_type_object)) throw std::runtime_error("analysis configuration is missing object fields");
        for (const char *name : {"eagle-pe", "eagle-analysis", "eagle-intel", "eagle-yara"})
            if (!fs::is_regular_file(native / name) || access((native / name).c_str(), X_OK)) throw std::runtime_error("required native analysis helper is unavailable");
        rules = get(request, "rules") ? fs::path(text(get(request, "rules"))) : native.parent_path() / "engine/eagle.yar";
        if (auto *work = get(request, "work")) workspace = text(work);
        else if (const char *work = getenv("TMPDIR")) workspace = work;
        if (auto *python = get(request, "extractor_python")) extractor_python = text(python);
        if (auto *database = get(request, "database")) databases.emplace_back(text(database));
        else if (const char *database = getenv("EAGLE_INTEL_DB")) databases.emplace_back(database);
        else
        {
            if (const char *data = getenv("XDG_DATA_HOME")) databases.emplace_back(fs::path(data) / "bottles/eagle_intel.sqlite");
            else if (const char *home = getenv("HOME")) databases.emplace_back(fs::path(home) / ".local/share/bottles/eagle_intel.sqlite");
            databases.emplace_back(native.parent_path() / "engine/eagle-intel.sqlite");
        }
    }
    json run()
    {
        auto basename = target.filename().string();
        std::string extension = target.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) { return std::tolower(ch); });
        step("Initialising Eagle..."); step("Target: " + basename);
        for (const char *name : {"Graphics", "Audio", "Runtimes", "Input", "Social/DRM", "Engines", "Frameworks", "Protection", "Packers", "Physics", "Media", "Crypto", "Upscaling", "Installer", "Warning", "Registry", "Analysed Files"}) json_object_object_add(details.get(), name, json_object_new_array());
        json_object_array_add(get(details.get(), "Analysed Files"), json_object_new_string(basename.c_str()));
        if (extension == ".msi")
        {
            step("MSI package detected - extracting for analysis...");
            auto value = object(); string(value.get(), "name", "MSI"); string(value.get(), "source", "File Extension"); json_object_array_add(get(details.get(), "Installer"), value.release());
            extraction output(workspace); auto files = installer("MSI", output.path); scan_installer(files, false);
            step("Querying community intelligence..."); auto product = target.stem().string(); auto plan = intelligence(nullptr, product);
            auto request = object(); json_object_object_add(request.get(), "suggestions", json_object_new_array()); set(request.get(), "intel", plan.get()); auto suggestions = call("merge", std::move(request));
            auto report = object(); string(report.get(), "name", basename); string(report.get(), "product_name", product);
            for (const char *key : {"publisher", "arch", "min_os"}) string(report.get(), key, "Unknown");
            json_object_object_add(report.get(), "admin", json_object_new_boolean(false)); json_object_object_add(report.get(), "frameworks", json_object_new_array());
            set(report.get(), "suggestions", suggestions.get()); set(report.get(), "details", details.get()); json_object_object_add(report.get(), "metadata", json_object_new_object()); set(report.get(), "intel", plan.get());
            step("MSI analysis complete."); return report;
        }
        step("Loading PE structure (Could take a while)...");
        auto structure = tool({(native / "eagle-pe").string(), target.string()});
        auto metadata = object();
        for (const char *key : {"compiler", "build_date", "packer"}) set(metadata.get(), key, nullptr);
        for (const char *key : {"is_packed", "large_address_aware", "dep_enabled", "aslr_enabled", "is_debug"}) json_object_object_add(metadata.get(), key, json_object_new_boolean(false));
        auto request = object(); set(request.get(), "structure", structure.get()); set(request.get(), "details", details.get()); set(request.get(), "metadata", metadata.get()); string(request.get(), "basename", basename);
        for (const char *key : {"compilers", "packers", "mapping"}) set(request.get(), key, get(config.get(), key));
        auto interpreted = call("pe-insights", std::move(request));
        details = own(json_object_get(get(interpreted.get(), "details"))); metadata = own(json_object_get(get(interpreted.get(), "metadata"))); steps(interpreted.get());
        step("Deep pattern scanning (YARA)..."); size_t matches = scan(target);
        if (matches) step("YARA: " + std::to_string(matches) + " patterns matched");
        step("Scanning directory structure..."); request = object(); string(request.get(), "path", target.string()); set(request.get(), "details", details.get());
        auto discovery = call("discover", std::move(request)); details = own(json_object_get(get(discovery.get(), "details"))); steps(discovery.get());
        auto archive = text(get(discovery.get(), "asar"));
        if (!archive.empty())
        {
            step("Analysing Electron archive...");
            extraction output(workspace);
            try
            {
                step("Extracting ASAR archive: " + fs::path(archive).filename().string() + "...");
                request = object(); string(request.get(), "path", archive); string(request.get(), "output", output.path.string());
                auto files = call("asar", std::move(request), 120);
                step("Extracted " + std::to_string(json_object_array_length(files.get())) + " files from ASAR");
                for (size_t index = 0; index < std::min(scan_limit, json_object_array_length(files.get())); index++)
                {
                    fs::path path(text(json_object_array_get_idx(files.get(), index))); auto name = path.filename().string();
                    step("Scanning ASAR content: " + name); scan(path, "Electron Source: " + name);
                }
            }
            catch (const analysis_cancelled &) { throw; }
            catch (const std::exception &error) { fprintf(stderr, "Eagle ASAR extraction failed: %s\n", error.what()); }
        }
        step("Scanning neighbor files..."); auto *neighbors = get(discovery.get(), "neighbors");
        if (!json_object_get_boolean(get(discovery.get(), "neighbor_scan_allowed"))) step("Skipping neighbor scan (Common directory detected)");
        if (json_object_array_length(neighbors))
        {
            step("Found " + std::to_string(json_object_array_length(neighbors)) + " neighbor files. Ensure directory is clean to avoid false positives.");
            auto warning = object(); string(warning.get(), "name", "Mixed Files Risk"); string(warning.get(), "description", "Neighbor files were analyzed. Ensure all files in this directory belong to the same software to avoid false positives."); string(warning.get(), "severity", "warning"); string(warning.get(), "source", "Context Scanner"); json_object_array_add(get(details.get(), "Warning"), warning.release());
        }
        for (size_t index = 0; index < std::min<size_t>(20, json_object_array_length(neighbors)); index++)
        {
            fs::path path(text(json_object_array_get_idx(neighbors, index))); auto name = path.filename().string(); bool seen = false;
            auto *analysed = get(details.get(), "Analysed Files");
            for (size_t item = 0; item < json_object_array_length(analysed); item++) seen |= text(json_object_array_get_idx(analysed, item)) == name;
            if (seen || path == target) continue;
            step("Scanning context: " + name); scan(path, "Neighbor: " + name);
            std::string lower = name; std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) { return std::tolower(ch); });
            if (auto *mapping = get(get(config.get(), "mapping"), lower.c_str()))
            {
                auto label = text(json_object_array_get_idx(mapping, 0)), category = text(json_object_array_get_idx(mapping, 1));
                auto *items = get(details.get(), category.c_str()); bool found = false;
                for (size_t item = 0; item < json_object_array_length(items); item++) found |= text(get(json_object_array_get_idx(items, item), "name")) == label;
                if (!found) { auto value = object(); string(value.get(), "name", label); string(value.get(), "source", "Neighbor: " + name); json_object_array_add(items, value.release()); }
            }
            json_object_array_add(get(details.get(), "Analysed Files"), json_object_new_string(name.c_str()));
        }
        if (json_object_array_length(get(details.get(), "Installer")))
        {
            auto *item = json_object_array_get_idx(get(details.get(), "Installer"), 0);
            auto type = json_object_is_type(item, json_type_object) ? text(get(item, "name")) : text(item);
            step("Installer detected (" + type + "), performing deep scan...");
            extraction output(workspace);
            try
            {
                auto files = installer(type, output.path);
                fs::path largest;
                for (const auto &file : files)
                {
                    auto extension = file.extension().string();
                    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) { return std::tolower(ch); });
                    if (extension == ".exe" && (largest.empty() || fs::file_size(file) > fs::file_size(largest))) largest = file;
                }
                if (!largest.empty()) { step("Scanning main binary: " + largest.filename().string()); scan_installer(files, true); }
            }
            catch (const analysis_cancelled &) { throw; }
            catch (const std::exception &error) { fprintf(stderr, "Eagle deep scan failed: %s\n", error.what()); step("Deep scan failed, continuing with surface analysis"); }
        }
        step("Querying community intelligence..."); auto plan = intelligence(structure.get(), text(get(interpreted.get(), "product_name")));
        step("Generating optimisation suggestions..."); request = object(); set(request.get(), "details", details.get()); set(request.get(), "metadata", metadata.get());
        for (const char *key : {"is_net", "dpi_aware"}) set(request.get(), key, get(interpreted.get(), key));
        auto shipping = text(get(discovery.get(), "ue_shipping_exe")); if (shipping.empty()) set(request.get(), "ue_shipping_exe", nullptr); else string(request.get(), "ue_shipping_exe", shipping);
        set(request.get(), "intel", plan.get()); auto advice = call("recommend", std::move(request));
        auto report = object(); string(report.get(), "name", basename);
        for (const char *key : {"product_name", "publisher", "arch", "min_os", "admin"}) set(report.get(), key, get(interpreted.get(), key));
        for (const char *key : {"frameworks", "suggestions", "messages"}) set(report.get(), key, get(advice.get(), key));
        set(report.get(), "details", details.get()); set(report.get(), "metadata", metadata.get()); set(report.get(), "intel", plan.get());
        step("Analysis complete."); return report;
    }
};

int main(int argc, char **argv)
{
    if (argc != 1) { fputs("usage: eagle-driver < REQUEST\n", stderr); return 2; }
    signal(SIGPIPE, SIG_IGN);
    struct sigaction action = {};
    action.sa_handler = interrupt; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr)) { fputs("cannot install analysis interruption handlers\n", stderr); return 1; }
    try
    {
        std::string input; char buffer[4096];
        while (size_t count = fread(buffer, 1, sizeof(buffer), stdin)) { check_cancelled(); input.append(buffer, count); if (input.size() > 1024 * 1024) throw std::runtime_error("request exceeds limit"); }
        check_cancelled();
        if (prctl(PR_SET_CHILD_SUBREAPER, 1)) throw std::runtime_error("cannot collect analysis helper descendants");
        auto request = parse(input);
        if (!json_object_is_type(request.get(), json_type_object)) throw std::runtime_error("analysis request must be an object");
        analyzer engine(fs::canonical(argv[0]), request.get()); auto report = engine.run(); check_cancelled(); auto result = object();
        json_object_object_add(result.get(), "status", json_object_new_boolean(true)); set(result.get(), "data", report.get()); puts(encode(result.get()).c_str()); return 0;
    }
    catch (const analysis_cancelled &error)
    {
        auto result = object(); json_object_object_add(result.get(), "status", json_object_new_boolean(false)); json_object_object_add(result.get(), "cancelled", json_object_new_boolean(true)); string(result.get(), "error", error.what()); puts(encode(result.get()).c_str()); return 128 + cancel_signal;
    }
    catch (const std::exception &error)
    {
        auto result = object(); json_object_object_add(result.get(), "status", json_object_new_boolean(false)); string(result.get(), "error", error.what()); puts(encode(result.get()).c_str()); return 1;
    }
}
