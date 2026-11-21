// Pheonix Dynamic Loader C Source Code
#define __IPSTDLIB_BUILD
#include <pdl.h>

#include <pstdlib.h>
#include <pio.h>

#include <elf.h>

static const char* _pdl_error = NULL;

// Internal structures
typedef enum PDLFormat {
    PDL_FORMAT_UNKNOWN = 0,
    PDL_FORMAT_ELF,
    PDL_FORMAT_PE
};

struct PDLHdr {
	const char* path; // Library path
	
	enum PDLFormat format; // Library format
	PDLOpenModes open_mode; // Mode via which lib was opened
	PDLOpenFlags open_flags; // Flags via which lib was opened

	void* lib_base; // Loaded library pointer
	usize_t lib_size; // Loaded library size
};

struct PDLElfInfo {
	bool _is64bit; // ELFCLASS64
	bool _isle; // ELFDATA2LSB
};

// ELF

static bool _pdl_elf64_load_contains_file(const Elf64_Phdr* load, const Elf64_Phdr* other) {
    if (other->p_offset < load->p_offset) return false;

    u64 delta = other->p_offset - load->p_offset;
    return delta <= load->p_filesz && other->p_filesz <= load->p_filesz - delta;
}

static bool _pdl_elf64_load_contains_memory(const Elf64_Phdr* load, const Elf64_Phdr* other) {
    if (other->p_vaddr < load->p_vaddr) return false;

    u64 delta = other->p_vaddr - load->p_vaddr;
    return delta <= load->p_memsz && other->p_memsz <= load->p_memsz - delta;
}

static bool _pdl_elf64_validate_load_relationships(const Elf64_Phdr* phdrs, usize_t phnum) {
    for (usize_t i = 0; i < phnum; i++) {
        const Elf64_Phdr* other = &phdrs[i];
        bool needs_file = false;
        bool needs_memory = false;

        switch (other->p_type) {
            case PT_DYNAMIC:
            case PT_TLS:
            case PT_PHDR: needs_file = true; needs_memory = true; break;
            case PT_GNU_RELRO:
            case PT_GNU_EH_FRAME: needs_memory = true; break;
            default: continue;
        }

        bool found = false;
        for (usize_t j = 0; j < phnum; j++) {
            const Elf64_Phdr* load = &phdrs[j];

            if (load->p_type != PT_LOAD) continue;
            if (needs_file && !_pdl_elf64_load_contains_file(load, other)) continue;
            if (needs_memory && !_pdl_elf64_load_contains_memory(load, other)) continue;

            found = true;
            break;
        }

        if (!found) return false;
    }

    return true;
}

static bool _pdl_validate_elf64(PIO_Stream* f, ulen_t size, struct PDLElfInfo* inout) {
	if (!f || size < sizeof(Elf64_Ehdr) || !inout) return false;
	if (!inout->_is64bit) return false;

	Elf64_Ehdr hdr = {0};
	if (sread(f, &hdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) return false;

	if (hdr.e_type != ET_DYN) return false; //! ONLY Shared Dynamic Files (.so)
	if (hdr.e_machine != EM_X86_64) return false; // TODO: Make it validate with host machine
	if (hdr.e_version != EV_CURRENT) return false;
	
	if (hdr.e_phoff < sizeof(Elf64_Ehdr) || hdr.e_phoff > size) return false;
	if (hdr.e_phentsize != sizeof(Elf64_Phdr)) return false;
	if (hdr.e_phnum < 1) return false;
	if (hdr.e_phnum > (size - hdr.e_phoff) / hdr.e_phentsize || hdr.e_phnum < (sizeof(Elf64_Ehdr) - hdr.e_phoff) / hdr.e_phentsize) return false;

	if (hdr.e_shnum > 0) {
		if (hdr.e_shoff < sizeof(Elf64_Ehdr) || hdr.e_shoff > size) return false;
		if (hdr.e_shentsize != sizeof(Elf64_Shdr)) return false;
		if (hdr.e_shnum > (size - hdr.e_shoff) / hdr.e_shentsize || hdr.e_shnum < (sizeof(Elf64_Ehdr) - hdr.e_shoff) / hdr.e_shentsize) return false;
	}
	if ((hdr.e_shstrndx < 1 || hdr.e_shstrndx >= hdr.e_shnum) && hdr.e_shstrndx != SHN_UNDEF) return false; //! XINDEX Not yet supported

	usize_t phdrs_size = hdr.e_phentsize*hdr.e_phnum;
	Elf64_Phdr* phdrs = alloc(phdrs_size);
	if (!phdrs) return false;

	if (!sseek(f, hdr.e_phoff, SEEK_SET)) goto phdrs_error;
	if (sread(f, phdrs, phdrs_size) != phdrs_size) goto phdrs_error;

	bool found_dyn_phdr = false;
	bool found_tls_phdr = false;
	bool found_gnu_stack_phdr = false;
	bool found_gnu_relro_phdr = false;
	bool found_phdr_phdr = false;
	usize_t phdr_load_count = 0;

	for (usize_t i = 0; i < hdr.e_phnum; i++) {
		Elf64_Phdr* phdr = &phdrs[i];
		switch (phdr->p_type) {
			case PT_LOAD: break;
			case PT_DYNAMIC: break;
			case PT_INTERP: goto phdrs_error;
			case PT_TLS: break;
			case PT_GNU_STACK: break;
			case PT_GNU_RELRO: break;
			case PT_PHDR: break;

			default: continue;
		}

		if (!(phdr->p_offset <= size && phdr->p_filesz <= size - phdr->p_offset)) goto phdrs_error;
		if (phdr->p_filesz > phdr->p_memsz) goto phdrs_error;
		if (phdr->p_vaddr > UINT64_MAX - phdr->p_memsz) goto phdrs_error;
		
		if (phdr->p_align > 1){
			if (phdr->p_align & (phdr->p_align - 1)) goto phdrs_error;
			if ((phdr->p_vaddr % phdr->p_align) != (phdr->p_offset % phdr->p_align)) goto phdrs_error;
		}

		switch (phdr->p_type) {
			case PT_LOAD: {
				if (phdr->p_flags & ~(PF_R | PF_W | PF_X)) goto phdrs_error;
				if ((phdr->p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) goto phdrs_error;

				phdr_load_count++;
				break;
			}
			case PT_DYNAMIC: {
				if (phdr->p_filesz == 0 || phdr->p_filesz % sizeof(Elf64_Dyn) != 0) goto phdrs_error;

				if (found_dyn_phdr) goto phdrs_error;
				else found_dyn_phdr = true;
				break;
			}
			case PT_TLS: {
				if (found_tls_phdr) goto phdrs_error;
				else found_tls_phdr = true;
				
				break;
			}
			case PT_GNU_STACK: {
				if (phdr->p_flags & PF_X) goto phdrs_error;

				if (found_gnu_stack_phdr) goto phdrs_error;
				else found_gnu_stack_phdr = true;
				
				break;
			}
			case PT_GNU_RELRO: {
				if (found_gnu_relro_phdr) goto phdrs_error;
				else found_gnu_relro_phdr = true;
				
				break;
			}
			case PT_PHDR: {
				if (found_phdr_phdr) goto phdrs_error;
				else found_phdr_phdr = true;

				break;
			}

			default: break;
		}
	}

	if (phdr_load_count < 1) goto phdrs_error;
	if (!_pdl_elf64_validate_load_relationships(phdrs, hdr.e_phnum)) goto phdrs_error;

	goto phdrs_error_end;
	phdrs_error: {
		dealloc(phdrs);
		return false;
	}
	phdrs_error_end: {
		dealloc(phdrs);
	}


}


static bool _pdl_elf32_load_contains_file(const Elf32_Phdr* load, const Elf32_Phdr* other) {
    if (other->p_offset < load->p_offset) return false;

    u32 delta = other->p_offset - load->p_offset;
    return delta <= load->p_filesz && other->p_filesz <= load->p_filesz - delta;
}

static bool _pdl_elf32_load_contains_memory(const Elf32_Phdr* load, const Elf32_Phdr* other) {
    if (other->p_vaddr < load->p_vaddr) return false;

    u32 delta = other->p_vaddr - load->p_vaddr;
    return delta <= load->p_memsz && other->p_memsz <= load->p_memsz - delta;
}

static bool _pdl_elf32_validate_load_relationships(const Elf32_Phdr* phdrs, usize_t phnum) {
    for (usize_t i = 0; i < phnum; i++) {
        const Elf32_Phdr* other = &phdrs[i];
        bool needs_file = false;
        bool needs_memory = false;

        switch (other->p_type) {
            case PT_DYNAMIC:
            case PT_TLS:
            case PT_PHDR: needs_file = true; needs_memory = true; break;
            case PT_GNU_RELRO:
            case PT_GNU_EH_FRAME: needs_memory = true; break;
            default: continue;
        }

        bool found = false;
        for (usize_t j = 0; j < phnum; j++) {
            const Elf32_Phdr* load = &phdrs[j];

            if (load->p_type != PT_LOAD) continue;
            if (needs_file && !_pdl_elf64_load_contains_file(load, other)) continue;
            if (needs_memory && !_pdl_elf64_load_contains_memory(load, other)) continue;

            found = true;
            break;
        }

        if (!found) return false;
    }

    return true;
}

static bool _pdl_validate_elf32(PIO_Stream* f, ulen_t size, struct PDLElfInfo* inout) {
	if (!f || size < sizeof(Elf32_Ehdr) || !inout) return false;
	if (inout->_is64bit) return false;

	Elf32_Ehdr hdr = {0};
	if (sread(f, &hdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) return false;

	if (hdr.e_type != ET_DYN) return false; //! ONLY Shared Dynamic Files (.so)
	if (hdr.e_machine != EM_386) return false; // TODO: Make it validate with host machine
	if (hdr.e_version != EV_CURRENT) return false;
	
	if (hdr.e_phoff < sizeof(Elf32_Ehdr) || hdr.e_phoff > size) return false;
	if (hdr.e_phentsize != sizeof(Elf32_Phdr)) return false;
	if (hdr.e_phnum < 1) return false;
	if (hdr.e_phentsize > (size - hdr.e_phoff) / hdr.e_phnum || hdr.e_phentsize < (sizeof(Elf32_Ehdr) - hdr.e_phoff) / hdr.e_phnum) return false;

	if (hdr.e_shoff < sizeof(Elf32_Ehdr) || hdr.e_shoff > size) return false;
	if (hdr.e_shentsize != sizeof(Elf32_Shdr)) return false;
	if (hdr.e_shnum < 1) return false;
	if (hdr.e_shentsize > (size - hdr.e_shoff) / hdr.e_shnum || hdr.e_shentsize < (sizeof(Elf32_Ehdr) - hdr.e_shoff) / hdr.e_shnum) return false;

	if (hdr.e_phoff <= hdr.e_shoff && hdr.e_phoff+(hdr.e_phentsize*hdr.e_phnum) >= hdr.e_shoff) return false;
	if (hdr.e_phoff > hdr.e_shoff && hdr.e_phoff+(hdr.e_phentsize*hdr.e_phnum) >= hdr.e_shoff+(hdr.e_shentsize*hdr.e_shnum)) return false;
	if (hdr.e_shoff <= hdr.e_phoff && hdr.e_shoff+(hdr.e_shentsize*hdr.e_shnum) >= hdr.e_phoff) return false;
	if (hdr.e_shoff > hdr.e_phoff && hdr.e_shoff+(hdr.e_shentsize*hdr.e_shnum) >= hdr.e_phoff+(hdr.e_phentsize*hdr.e_phnum)) return false;

	if (hdr.e_shstrndx < 1 || hdr.e_shstrndx >= hdr.e_shnum) return false;


}


static bool _pdl_validate_elf(PIO_Stream* f, ulen_t size, struct PDLElfInfo* out) {
	if (size < EI_NIDENT || !f || !out) return false;

	char ident[EI_NIDENT];
	if (sread(f, ident, sizeof(ident)) != sizeof(ident)) return false;
	if (!sseek(f, SEEK_SET, 0)) return false;
	if (cmpbuf(ident, "\x7F\x45\x4C\x46", 4) != 0) return false;
	
	switch (ident[EI_CLASS]) {
		case ELFCLASS64: out->_is64bit = true; break;
		case ELFCLASS32: out->_is64bit = false; break;
		default: return false;
	}
	switch (ident[EI_DATA]) {
		case ELFDATA2LSB: out->_isle = true; break;
		case ELFDATA2MSB: out->_isle = false; break;
		default: return false;
	}

	if (ident[EI_VERSION] != EV_CURRENT) return false;
	// TODO: Add ABI verification

	if (out->_is64bit) return _pdl_validate_elf64(f, size, out);
	else return _pdl_validate_elf32(f, size, out);
}

__IFN PDLHandle pdl_open(const char* path, PDLOpenModes mode, PDLOpenFlags flags) {
	PIO_Stream* f = sopen_file(path, PSTREAM_FLAG_READ | PSTREAM_FLAG_BINARY);
	if (!f) return PDL_INVALID_HANDLE;

	if (!sseek(f, SEEK_END, 0)) {
		_pdl_error = "PDL_Error: Failed to seek to end in file";
		goto error;
	}

	len_t _sz = stell(f);
	if (_sz < 4) {
		_pdl_error = "PDL_Error: Size of file too small";
		goto error;
	}
	ulen_t size = (ulen_t)_sz;

	char magic[4];
	if (sread(f, magic, sizeof(magic)) != sizeof(magic)) {
		_pdl_error = "PDL_Error: Failed to properly read file";
		goto error;
	}

	enum PDLFormat format = PDL_FORMAT_UNKNOWN;
	if (cmpbuf(magic, "\x7F\x45\x4C\x46", 4) == 0) {
		// ELF File
		format = PDL_FORMAT_ELF;

		struct PDLElfInfo elfinfo = {0};
		if (!_pdl_validate_elf(f, size, &elfinfo)) {
			_pdl_error = "PDL_Error: File validation failed";
			goto error;
		}
	} else if (cmpbuf(magic, "\x4D\x5A", 2) == 0) {
		// PE File
		format = PDL_FORMAT_PE;
	} else {
		_pdl_error = "PDL_Error: Unsupported/Unknown file format";
		goto error;
	}

	struct PDLHdr* hdr = alloc(sizeof(struct PDLHdr));
	if (!hdr) {
		_pdl_error = "PDL_Error: Failed to allocate memory";
		goto error;
	}

	hdr->path = path;
	hdr->format = format;
	hdr->open_mode = mode;
	hdr->open_flags = flags;
	hdr->lib_size = size;

	return PDL_INVALID_HANDLE; // TODO: Fix

	error: {
		sclose(f);
		return PDL_INVALID_HANDLE;
	}
}
