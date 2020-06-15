import time
from ctypes import *
kernel32 = windll.kernel32

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
DEBUG_PROCESS = 0x00000001
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010

class STARTUPINFO(Structure):
    _fields_ = [
    ("cb", DWORD),
    ("lpReserved", LPTSTR),
    ("lpDesktop", LPTSTR),
    ("lpTitle", LPTSTR),
    ("dwX", DWORD),
    ("dwY", DWORD),
    ("dwXSize", DWORD),
    ("dwYSize", DWORD),
    ("dwXCountChars", DWORD),
    ("dwYCountChars", DWORD),
    ("dwFillAttribute",DWORD),
    ("dwFlags", DWORD),
    ("wShowWindow", WORD),
    ("cbReserved2", WORD),
    ("lpReserved2", LPBYTE),
    ("hStdInput", HANDLE),
    ("hStdOutput", HANDLE),
    ("hStdError", HANDLE),
]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
    ("hProcess", HANDLE),
    ("hThread", HANDLE),
    ("dwProcessId", DWORD),
    ("dwThreadId", DWORD),
]

class Runner:
    def __init__(self, command_line, debug = 0, show = True, suspended = False):
        self.command_line = command_line
        self.error_code = 0

        self.creation_flags = 0
        if debug:
            self.creation_flags |= DEBUG_PROCESS

        if suspended:
            self.creation_flags |= CREATE_SUSPENDED

        self.startup_info = STARTUPINFO()
        self.startup_info.cb = sizeof(self.startup_info)
        if show:
            self.startup_info.wShowWindow = 1
        else:
            self.startup_info.wShowWindow = 0
        self.startup_info.dwFlags = 0x1
       
        self.process_info = PROCESS_INFORMATION()

    def create(self):
        print("Creating process: " + self.command_line)
        if not kernel32.CreateProcessW(
                0,
                self.command_line,
                0,
                0,
                0,
                self.creation_flags,
                0,
                0,
                byref(self.startup_info),
                byref(self.process_info)):
            self.error_code = kernel32.GetLastError()
            print("[*] Error: 0x%08x." % (kernel32.GetLastError()))
            return False
        return True

    def get_id(self):
        return self.process_info.dwProcessId

    def resume(self):
        kernel32.ResumeThread(self.process_info.hThread)

if __name__ == '__main__':
    process = Runner("C:\\WINDOWS\\system32\\notepad.exe", suspended = True)
    process.create()
    print(process.get_id())
    time.sleep(5)
    process.resume()
