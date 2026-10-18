#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

class image
{
    int descriptor = -1;
    const unsigned char *data = nullptr;
    size_t length = 0;
    std::string build_id, debuglink;
    uint32_t debuglink_crc = 0;
    bool has_debug = false;
    void bounds(uint64_t offset, uint64_t size)
    {
        if (offset > length || size > length-offset) throw std::runtime_error("ELF field exceeds file bounds");
    }
    template<typename T> T read(uint64_t offset)
    {
        bounds(offset, sizeof(T)); T value; memcpy(&value, data+offset, sizeof(value)); return value;
    }
    std::string string(uint64_t offset, uint64_t size)
    {
        bounds(offset, size);
        size_t count = strnlen(reinterpret_cast<const char *>(data+offset), size);
        if (count == size) throw std::runtime_error("ELF string is not terminated");
        return std::string(reinterpret_cast<const char *>(data+offset), count);
    }
    void notes(uint64_t offset, uint64_t size)
    {
        bounds(offset, size);
        if (size > 16*1024*1024) throw std::runtime_error("ELF note section exceeds size limit");
        uint64_t end = offset+size;
        while (end-offset >= 12)
        {
            uint32_t names = read<uint32_t>(offset), bytes = read<uint32_t>(offset+4), type = read<uint32_t>(offset+8);
            offset += 12;
            uint64_t name_size = (static_cast<uint64_t>(names)+3) & ~uint64_t(3), payload_size = (static_cast<uint64_t>(bytes)+3) & ~uint64_t(3);
            if (name_size > end-offset || payload_size > end-offset-name_size) throw std::runtime_error("invalid ELF note bounds");
            if (type == NT_GNU_BUILD_ID && names == 4 && !memcmp(data+offset, "GNU", 4))
            {
                if (!bytes || bytes > 128) throw std::runtime_error("invalid ELF build ID size");
                std::string value;
                for (uint32_t i = 0; i < bytes; i++)
                {
                    char hex[3]; snprintf(hex, sizeof(hex), "%02x", data[offset+name_size+i]); value += hex;
                }
                if (!build_id.empty() && build_id != value) throw std::runtime_error("conflicting ELF build IDs");
                build_id = value;
            }
            offset += name_size+payload_size;
        }
    }
    static void quote(const std::string &value)
    {
        putchar('"');
        for (unsigned char ch : value)
        {
            if (ch == '\\' || ch == '"') printf("\\%c", ch);
            else if (ch < 32) printf("\\u%04x", ch);
            else putchar(ch);
        }
        putchar('"');
    }
    template<typename H, typename P, typename S> void inspect()
    {
        auto header = read<H>(0);
        if (header.e_ehsize != sizeof(H) || header.e_phnum == PN_XNUM || (header.e_shoff && !header.e_shnum) || header.e_shstrndx == SHN_XINDEX)
            throw std::runtime_error("unsupported ELF extended header");
        if (header.e_phnum && header.e_phentsize != sizeof(P)) throw std::runtime_error("invalid ELF program header size");
        bounds(header.e_phoff, static_cast<uint64_t>(header.e_phnum)*sizeof(P));
        uint64_t base = std::numeric_limits<uint64_t>::max(), end = 0;
        for (unsigned i = 0; i < header.e_phnum; i++)
        {
            auto program = read<P>(header.e_phoff+static_cast<uint64_t>(i)*sizeof(P));
            if (program.p_type == PT_NOTE) notes(program.p_offset, program.p_filesz);
            if (program.p_type == PT_LOAD)
            {
                bounds(program.p_offset, program.p_filesz);
                if (program.p_memsz > std::numeric_limits<uint64_t>::max()-program.p_vaddr) throw std::runtime_error("invalid ELF load range");
                base = std::min<uint64_t>(base, program.p_vaddr); end = std::max<uint64_t>(end, static_cast<uint64_t>(program.p_vaddr)+program.p_memsz);
            }
        }
        if (base == std::numeric_limits<uint64_t>::max()) base = 0;
        if (header.e_shnum)
        {
            if (header.e_shentsize != sizeof(S) || header.e_shstrndx >= header.e_shnum) throw std::runtime_error("invalid ELF section headers");
            bounds(header.e_shoff, static_cast<uint64_t>(header.e_shnum)*sizeof(S));
            auto names = read<S>(header.e_shoff+static_cast<uint64_t>(header.e_shstrndx)*sizeof(S));
            bounds(names.sh_offset, names.sh_size);
            for (unsigned i = 0; i < header.e_shnum; i++)
            {
                auto section = read<S>(header.e_shoff+static_cast<uint64_t>(i)*sizeof(S));
                if (section.sh_name >= names.sh_size) throw std::runtime_error("invalid ELF section name");
                auto name = string(names.sh_offset+section.sh_name, names.sh_size-section.sh_name);
                if (section.sh_type == SHT_NOTE) notes(section.sh_offset, section.sh_size);
                if (name == ".debug_info" || name == ".zdebug_info") has_debug = true;
                if (name == ".gnu_debuglink")
                {
                    debuglink = string(section.sh_offset, section.sh_size);
                    uint64_t crc_offset = (debuglink.size()+4) & ~uint64_t(3);
                    if (crc_offset+4 > section.sh_size) throw std::runtime_error("invalid ELF debuglink CRC");
                    debuglink_crc = read<uint32_t>(section.sh_offset+crc_offset);
                }
            }
        }
        printf("{\"format\":\"ELF\",\"machine\":%u,\"type\":%u,\"image_base\":\"0x%llx\",\"size\":%llu,\"entry\":\"0x%llx\",\"build_id\":", header.e_machine, header.e_type, static_cast<unsigned long long>(base), static_cast<unsigned long long>(end-base), static_cast<unsigned long long>(header.e_entry));
        quote(build_id); printf(",\"debug_info\":%s,\"debuglink\":", has_debug ? "true" : "false"); quote(debuglink);
        printf(",\"debuglink_crc\":%u}\n", debuglink_crc);
    }
public:
    explicit image(const char *path)
    {
        descriptor = open(path, O_RDONLY);
        struct stat status;
        if (descriptor < 0 || fstat(descriptor, &status) || !S_ISREG(status.st_mode) || status.st_size < EI_NIDENT)
        { if (descriptor >= 0) close(descriptor); throw std::runtime_error("cannot read ELF image"); }
        length = status.st_size;
        void *mapping = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, descriptor, 0);
        if (mapping == MAP_FAILED) { close(descriptor); throw std::runtime_error("cannot map ELF image"); }
        data = static_cast<const unsigned char *>(mapping);
    }
    ~image() { munmap(const_cast<unsigned char *>(data), length); close(descriptor); }
    void inspect()
    {
        if (memcmp(data, ELFMAG, SELFMAG) || data[EI_DATA] != ELFDATA2LSB || data[EI_VERSION] != EV_CURRENT)
            throw std::runtime_error("unsupported ELF encoding");
        if (data[EI_CLASS] == ELFCLASS64) inspect<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr>();
        else if (data[EI_CLASS] == ELFCLASS32) inspect<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr>();
        else throw std::runtime_error("unsupported ELF class");
    }
};

int main(int argc, char **argv)
{
    if (argc != 2) { fputs("usage: eagle-elf IMAGE\n", stderr); return 2; }
    try { image file(argv[1]); file.inspect(); return 0; }
    catch (const std::exception &error) { fprintf(stderr, "%s\n", error.what()); return 1; }
}
