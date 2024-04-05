#pragma once
#include <Windows.h>
#include <string>
#include <iostream>

class BYOVD_PROVIDER 
{
    HANDLE _device {INVALID_HANDLE_VALUE};
    char _device_name[FILENAME_MAX];
    char _driver_name[FILENAME_MAX];
    char _driver_path[FILENAME_MAX];
    char _service_name[FILENAME_MAX];

    bool file_exists();
    void create_service();
    bool load_driver();
    bool is_mandatory_high_process();
    void remove_service();

public:
    bool WriteVirtualMemory(ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
    bool ReadVirtualMemory(ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);  
    BYOVD_PROVIDER(const std::string& driver_name, const std::string& device_name);
    ~BYOVD_PROVIDER();
};