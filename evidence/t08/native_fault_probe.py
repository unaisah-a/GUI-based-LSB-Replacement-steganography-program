"""Diagnostic only: identify the native module at an access violation."""
import ctypes
import os
import sys

import pytest


class Record(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ulong), ("flags", ctypes.c_ulong),
                ("previous", ctypes.c_void_p), ("address", ctypes.c_void_p)]


class Pointers(ctypes.Structure):
    _fields_ = [("record", ctypes.POINTER(Record)), ("context", ctypes.c_void_p)]


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.GetModuleHandleExW.argtypes = [ctypes.c_ulong, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
CALLBACK = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.POINTER(Pointers))


@CALLBACK
def report(info):
    record = info.contents.record.contents
    if record.code == 0xC0000005:
        module = ctypes.c_void_p()
        kernel.GetModuleHandleExW(6, record.address, ctypes.byref(module))
        path = ctypes.create_unicode_buffer(32768)
        kernel.GetModuleFileNameW(module, path, len(path))
        line = f"NATIVE FAULT: {path.value} + {record.address - (module.value or 0):#x}\n"
        os.write(2, line.encode("utf-8"))
    return 0  # Continue normal exception handling; do not suppress the crash.


kernel.AddVectoredExceptionHandler.argtypes = [ctypes.c_ulong, CALLBACK]
kernel.AddVectoredExceptionHandler.restype = ctypes.c_void_p
kernel.AddVectoredExceptionHandler(1, report)
sys.exit(pytest.main(sys.argv[1:]))
