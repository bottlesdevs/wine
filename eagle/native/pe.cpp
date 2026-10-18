#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include "ordinals.h"

struct section { uint32_t rva, virtual_size, raw, size; std::string name; };

static void quote(const std::string &value)
{
    putchar('"');
    for (unsigned char ch : value)
    {
        if (ch == '"' || ch == '\\') printf("\\%c", ch);
        else if (ch < 32) printf("\\u%04x", ch);
        else putchar(ch);
    }
    putchar('"');
}

class image
{
    int descriptor;
    const uint8_t *data;
    size_t length;
    std::vector<section> sections;
    uint32_t headers;
    std::map<std::string, std::string> version;
    std::vector<std::string> manifests;
    std::vector<std::string> import_names;
public:
    explicit image(const char *path)
    {
        struct stat info;
        descriptor = open(path, O_RDONLY | O_CLOEXEC);
        if (descriptor < 0) throw std::runtime_error("cannot open PE image");
        if (fstat(descriptor, &info) || info.st_size < 64)
        {
            close(descriptor); throw std::runtime_error("PE image is truncated");
        }
        length = static_cast<size_t>(info.st_size);
        data = static_cast<const uint8_t *>(mmap(nullptr, length, PROT_READ, MAP_PRIVATE, descriptor, 0));
        if (data == MAP_FAILED) { close(descriptor); throw std::runtime_error("cannot map PE image"); }
    }
    ~image() { munmap(const_cast<uint8_t *>(data), length); close(descriptor); }
    image(const image &) = delete;
    image &operator=(const image &) = delete;

    void bounds(size_t offset, size_t size) const
    {
        if (offset > length || size > length - offset) throw std::runtime_error("PE field is out of bounds");
    }
    uint16_t word(size_t offset) const
    {
        bounds(offset, 2); return data[offset] | static_cast<uint16_t>(data[offset+1]) << 8;
    }
    uint32_t dword(size_t offset) const
    {
        bounds(offset, 4); return word(offset) | static_cast<uint32_t>(word(offset+2)) << 16;
    }
    std::string text(size_t offset, size_t maximum = 4096) const
    {
        bounds(offset, 1);
        size_t count = 0;
        while (count < maximum && count < length - offset && data[offset+count]) count++;
        if (count == maximum || count == length - offset) throw std::runtime_error("unterminated PE string");
        return std::string(reinterpret_cast<const char *>(data + offset), count);
    }
    size_t file_offset(uint32_t rva, size_t size = 1) const
    {
        if (rva < headers) { bounds(rva, size); return rva; }
        for (const auto &entry : sections)
        {
            if (rva >= entry.rva && static_cast<uint64_t>(rva) - entry.rva < entry.size)
            {
                size_t offset = static_cast<size_t>(entry.raw) + rva - entry.rva;
                if (size > entry.size - (rva - entry.rva)) throw std::runtime_error("PE field spans raw section boundary");
                bounds(offset, size); return offset;
            }
        }
        throw std::runtime_error("PE RVA is not backed by file data");
    }
    std::string wide(size_t start, size_t units) const
    {
        bounds(start, units * 2);
        std::string result;
        for (size_t index = 0; index < units; index++)
        {
            uint32_t code = word(start + index * 2);
            if (!code) break;
            if (code >= 0xd800 && code <= 0xdbff && index + 1 < units)
            {
                uint32_t next = word(start + (index + 1) * 2);
                if (next >= 0xdc00 && next <= 0xdfff) { code = 0x10000 + ((code-0xd800) << 10) + next-0xdc00; index++; }
                else code = 0xfffd;
            }
            else if (code >= 0xd800 && code <= 0xdfff) code = 0xfffd;
            if (code < 0x80) result += static_cast<char>(code);
            else if (code < 0x800) { result += static_cast<char>(0xc0 | (code >> 6)); result += static_cast<char>(0x80 | (code & 63)); }
            else if (code < 0x10000) { result += static_cast<char>(0xe0 | (code >> 12)); result += static_cast<char>(0x80 | ((code >> 6) & 63)); result += static_cast<char>(0x80 | (code & 63)); }
            else { result += static_cast<char>(0xf0 | (code >> 18)); result += static_cast<char>(0x80 | ((code >> 12) & 63)); result += static_cast<char>(0x80 | ((code >> 6) & 63)); result += static_cast<char>(0x80 | (code & 63)); }
        }
        return result;
    }
    void version_block(size_t start, size_t end, unsigned depth)
    {
        if (depth > 8 || end < start || end - start < 6) throw std::runtime_error("invalid version block");
        uint16_t size = word(start), value_size = word(start+2), type = word(start+4);
        if (size < 6 || size > end-start) throw std::runtime_error("invalid version block length");
        end = start + size;
        size_t position = start + 6, key_start = position;
        while (position + 2 <= end && word(position)) position += 2;
        if (position + 2 > end) throw std::runtime_error("version key is truncated");
        std::string key = wide(key_start, (position-key_start)/2);
        position = (position + 2 + 3) & ~size_t(3);
        size_t bytes = type == 1 ? static_cast<size_t>(value_size) * 2 : value_size;
        if (position > end || bytes > end-position) throw std::runtime_error("version value is truncated");
        if (type == 1 && value_size) version[key] = wide(position, value_size);
        position = (position + bytes + 3) & ~size_t(3);
        while (position + 6 <= end)
        {
            uint16_t child_size = word(position);
            if (!child_size) break;
            version_block(position, end, depth+1);
            position = (position + child_size + 3) & ~size_t(3);
        }
    }
    void resource_directory(size_t base, uint32_t relative, unsigned depth, uint32_t kind, unsigned &visited)
    {
        if (depth > 4 || ++visited > 4096) throw std::runtime_error("resource tree exceeds limits");
        size_t root = base + relative;
        bounds(root, 16);
        unsigned count = word(root+12) + word(root+14);
        if (count > 4096) throw std::runtime_error("resource entries exceed limits");
        bounds(root+16, static_cast<size_t>(count) * 8);
        for (unsigned index = 0; index < count; index++)
        {
            size_t entry = root + 16 + index * 8;
            uint32_t id = dword(entry), offset = dword(entry+4);
            uint32_t type = depth == 0 ? id : kind;
            if (type != 16 && type != 24) continue;
            if (offset & 0x80000000) resource_directory(base, offset & 0x7fffffff, depth+1, type, visited);
            else
            {
                size_t record = base + offset;
                bounds(record, 16);
                uint32_t rva = dword(record), size = dword(record+4);
                if (size > 2 * 1024 * 1024) throw std::runtime_error("resource payload exceeds limits");
                size_t position = file_offset(rva, size);
                if (type == 16 && version.empty()) version_block(position, position+size, 0);
                if (type == 24)
                {
                    if (size >= 2 && word(position) == 0xfeff) manifests.push_back(wide(position+2, (size-2)/2));
                    else manifests.emplace_back(reinterpret_cast<const char *>(data+position), size);
                }
            }
        }
    }
    void print()
    {
        if (word(0) != 0x5a4d) throw std::runtime_error("not a DOS image");
        size_t pe = dword(0x3c);
        if (dword(pe) != 0x4550) throw std::runtime_error("not a PE image");
        uint16_t count = word(pe+6), optional_size = word(pe+20);
        size_t optional = pe+24;
        bounds(optional, optional_size);
        uint16_t magic = word(optional);
        if (magic != 0x10b && magic != 0x20b) throw std::runtime_error("unsupported optional header");
        size_t directory_start = optional + (magic == 0x20b ? 112 : 96);
        uint64_t image_base = magic == 0x20b ? static_cast<uint64_t>(dword(optional+28)) << 32 | dword(optional+24) : dword(optional+28);
        uint32_t directory_count = dword(optional + (magic == 0x20b ? 108 : 92));
        if (count > 96 || directory_count > 16 || directory_start + directory_count * 8 > optional + optional_size) throw std::runtime_error("invalid PE header counts");
        headers = dword(optional+60);
        for (unsigned index = 0; index < count; index++)
        {
            size_t offset = optional + optional_size + index * 40;
            bounds(offset, 40);
            std::string name(reinterpret_cast<const char *>(data + offset), strnlen(reinterpret_cast<const char *>(data+offset), 8));
            sections.push_back({dword(offset+12), dword(offset+8), dword(offset+20), dword(offset+16), name});
        }
        auto directory = [&](unsigned index) -> uint32_t { return index < directory_count ? dword(directory_start + index * 8) : 0; };
        std::string resource_error;
        if (directory(2))
        {
            unsigned visited = 0;
            try { resource_directory(file_offset(directory(2), 16), 0, 0, 0, visited); }
            catch (const std::exception &error) { resource_error = error.what(); }
        }
        printf("{\"machine\":%u,\"timestamp\":%u,\"size\":%u,\"entry_rva\":%u,\"min_os\":\"%u.%u\",\"characteristics\":%u,\"dll_characteristics\":%u,\"image_base\":\"0x%llx\",\"codeview\":[", word(pe+4), dword(pe+8), dword(optional+56), dword(optional+16), word(optional+40), word(optional+42), word(pe+22), word(optional+70), static_cast<unsigned long long>(image_base));
        bool comma = false;
        if (directory(6))
        {
            uint32_t size = dword(directory_start + 6*8+4);
            if (size > 28 * 4096 || size % 28) throw std::runtime_error("invalid debug directory");
            size_t offset = file_offset(directory(6), size);
            for (uint32_t index = 0; index < size / 28; index++)
            {
                size_t record = offset + index * 28;
                uint32_t raw = dword(record+24), bytes = dword(record+16);
                if (dword(record+12) != 2 || bytes < 24) continue;
                bounds(raw, bytes);
                if (dword(raw) != 0x53445352) continue;
                if (comma) putchar(',');
                comma = true;
                printf("{\"guid\":\"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\",\"age\":%u,\"pdb\":", dword(raw+4), word(raw+8), word(raw+10), data[raw+12], data[raw+13], data[raw+14], data[raw+15], data[raw+16], data[raw+17], data[raw+18], data[raw+19], dword(raw+20));
                quote(text(raw+24, bytes-24)); putchar('}');
            }
        }
        printf("],\"imports\":["); comma = false;
        for (unsigned kind : {1u, 13u}) if (directory(kind))
        {
            size_t stride = kind == 1 ? 20 : 32;
            bool ended = false;
            for (unsigned index = 0; index < 4096; index++)
            {
                uint64_t rva = static_cast<uint64_t>(directory(kind)) + index * stride;
                if (rva > UINT32_MAX) throw std::runtime_error("import RVA overflow");
                size_t offset = file_offset(static_cast<uint32_t>(rva), stride);
                uint32_t name = dword(offset + (kind == 1 ? 12 : 4));
                if (!name) { ended = true; break; }
                if (kind == 13 && !(dword(offset) & 1))
                {
                    if (name < image_base) throw std::runtime_error("invalid legacy delay import VA");
                    name -= static_cast<uint32_t>(image_base);
                }
                if (comma) putchar(',');
                comma = true;
                printf("{\"name\":"); quote(text(file_offset(name)));
                printf(",\"delay\":%s}", kind == 13 ? "true" : "false");
                if (kind == 1)
                {
                    std::string dll = text(file_offset(name));
                    std::transform(dll.begin(), dll.end(), dll.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    std::string library = dll;
                    size_t dot = library.rfind('.');
                    if (dot != std::string::npos && (library.substr(dot+1) == "dll" || library.substr(dot+1) == "sys" || library.substr(dot+1) == "ocx")) library.resize(dot);
                    uint32_t thunk_rva = dword(offset);
                    if (!thunk_rva) thunk_rva = dword(offset+16);
                    size_t stride = magic == 0x20b ? 8 : 4;
                    bool terminated = false;
                    for (unsigned function = 0; function < 16384; function++)
                    {
                        uint64_t rva = static_cast<uint64_t>(thunk_rva) + function * stride;
                        if (rva > UINT32_MAX) throw std::runtime_error("import thunk RVA overflow");
                        size_t thunk = file_offset(static_cast<uint32_t>(rva), stride);
                        uint64_t value = dword(thunk);
                        if (stride == 8) value |= static_cast<uint64_t>(dword(thunk+4)) << 32;
                        if (!value) { terminated = true; break; }
                        std::string symbol;
                        uint64_t ordinal_mask = uint64_t(1) << (stride == 8 ? 63 : 31);
                        if (value & ordinal_mask)
                        {
                            unsigned ordinal = value & 0xffff;
                            auto table = ordinal_names.find(dll);
                            if (table != ordinal_names.end())
                            {
                                auto item = table->second.find(ordinal);
                                if (item != table->second.end()) symbol = item->second;
                            }
                            if (symbol.empty()) symbol = "ord" + std::to_string(ordinal);
                        }
                        else
                        {
                            if (value > UINT32_MAX-2) throw std::runtime_error("import symbol RVA overflow");
                            symbol = text(file_offset(static_cast<uint32_t>(value)+2));
                        }
                        std::transform(symbol.begin(), symbol.end(), symbol.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                        if (import_names.size() >= 65536) throw std::runtime_error("import symbol count exceeds limits");
                        import_names.push_back(library + "." + symbol);
                    }
                    if (!terminated) throw std::runtime_error("unterminated import thunk list");
                }
            }
            if (!ended) throw std::runtime_error("unterminated import directory");
        }
        printf("],\"sections\":["); comma = false;
        for (const auto &entry : sections)
        {
            if (comma) putchar(',');
            comma = true;
            printf("{\"name\":"); quote(entry.name);
            printf(",\"rva\":%u,\"virtual_size\":%u,\"raw_size\":%u}", entry.rva, entry.virtual_size, entry.size);
        }
        printf("],\"managed\":%s,\"rich_products\":[", directory(14) && dword(directory_start+14*8+4) ? "true" : "false");
        comma = false;
        for (size_t rich = 64; rich + 8 <= pe; rich += 4) if (dword(rich) == 0x68636952)
        {
            uint32_t key = dword(rich+4);
            for (size_t start = rich; start >= 64; start -= 4) if ((dword(start) ^ key) == 0x536e6144)
            {
                for (size_t entry = start+16; entry+8 <= rich; entry += 8)
                {
                    if (comma) putchar(',');
                    comma = true;
                    printf("%u", (dword(entry) ^ key) >> 16);
                }
                break;
            }
            break;
        }
        printf("],\"version\":{"); comma = false;
        for (const auto &entry : version)
        {
            if (comma) putchar(',');
            comma = true; quote(entry.first); putchar(':'); quote(entry.second);
        }
        printf("},\"manifests\":["); comma = false;
        for (const auto &manifest : manifests)
        {
            if (comma) putchar(',');
            comma = true; quote(manifest);
        }
        printf("],\"resource_error\":"); quote(resource_error);
        printf(",\"imphash_material\":");
        std::string material;
        for (const auto &name : import_names) { if (!material.empty()) material += ','; material += name; }
        quote(material); printf("}\n");
    }
};

int main(int argc, char **argv)
{
    if (argc != 2) { fputs("usage: eagle-pe IMAGE\n", stderr); return 2; }
    try { image file(argv[1]); file.print(); return 0; }
    catch (const std::exception &error) { fprintf(stderr, "%s\n", error.what()); return 1; }
}
