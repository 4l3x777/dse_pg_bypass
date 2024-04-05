#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <iostream>

class KernelUtils
{
    inline static std::string kernel_path = "c:\\windows\\system32\\ntoskrnl.exe";
public:
    static DWORD64 ntoskrnl_base();
    static DWORD64 get_sevalidateimageheader_offset();
    static DWORD64 get_sevalidateimagedata_offset();
    static DWORD64 get_ret_offset();
    static DWORD64 get_patchguard_offset();
    static DWORD64 get_patchguardvalue_offset();

};