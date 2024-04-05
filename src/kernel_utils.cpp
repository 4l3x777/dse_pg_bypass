#include <kernel_utils.h>
#include <pattern.h>

DWORD64 KernelUtils::ntoskrnl_base() 
{
	DWORD cbNeeded = 0;
	LPVOID drivers[1024] = { 0 };
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) return (DWORD64)drivers[0];
	else return 0;
}

DWORD64 KernelUtils::get_sevalidateimageheader_offset()
{
	auto SeValidateImageHeader_sig = scanner::pattern(kernel_path.c_str()).scan_now("SeValidateImageHeader", "48 39 35 ? ? ? ? 48 8B F9 48 89 70 F0 44 8B DE").get_result();
	auto sig_pattern_begin = SeValidateImageHeader_sig.as<uint8_t*>(); 
	uint32_t rip_offset_SeValidateImageHeader_callback = *(uint32_t*)(&sig_pattern_begin[3]);
	uint32_t rip_instruction_length = 7;
	auto SeValidateImageHeader_callback_addr = SeValidateImageHeader_sig.add(rip_offset_SeValidateImageHeader_callback + rip_instruction_length).as<uint64_t*>();
	return (uint64_t)SeValidateImageHeader_callback_addr - (uint64_t)SeValidateImageHeader_sig.get_base<uint64_t*>();
}

DWORD64 KernelUtils::get_sevalidateimagedata_offset()
{
	auto SeValidateImageData_sig = scanner::pattern(kernel_path.c_str()).scan_now("SeValidateImageData", "48 8B 05 ? ? ? ? 4C 8B D1 48 85 C0 74 ?").get_result();
	auto sig_pattern_begin = SeValidateImageData_sig.as<uint8_t*>(); 
	uint32_t rip_offset_SeValidateImageData_callback = *(uint32_t*)(&sig_pattern_begin[3]);
	uint32_t rip_instruction_length = 7;
	auto SeValidateImageData_callback_addr = SeValidateImageData_sig.add(rip_offset_SeValidateImageData_callback + rip_instruction_length).as<uint64_t*>();
	return (uint64_t)SeValidateImageData_callback_addr - (uint64_t)SeValidateImageData_sig.get_base<uint64_t*>();
}

DWORD64 KernelUtils::get_ret_offset()
{
	auto ret_sig = scanner::pattern(kernel_path.c_str()).scan_now("ret", "B8 01 00 00 00 C3", ".text").get_result();
	auto ret_addr = ret_sig.as<uint64_t*>(); 
	return (uint64_t)ret_addr - (uint64_t)ret_sig.get_base<uint64_t*>();       
}

DWORD64 KernelUtils::get_patchguard_offset()
{
	auto PatchGuard_sig = scanner::pattern(kernel_path.c_str()).scan_now("PatchGuard", "38 0D ? ? ? ? 75 02 EB FE").get_result();
	auto sig_pattern_begin = PatchGuard_sig.as<uint8_t*>(); 
	uint32_t rip_offset_PatchGuard_callback = *(uint32_t*)(&sig_pattern_begin[2]);
	uint32_t rip_instruction_length = 6;
	auto PatchGuard_callback_addr = PatchGuard_sig.add(rip_offset_PatchGuard_callback + rip_instruction_length).as<uint64_t*>();
	return (uint64_t)PatchGuard_callback_addr - (uint64_t)PatchGuard_sig.get_base<uint64_t*>();
}

DWORD64 KernelUtils::get_patchguardvalue_offset()
{
	auto patchguardvalue_sig = scanner::pattern(kernel_path.c_str()).scan_now("patchguardvalue", "00 00 00 00 00 00 00 00", ".rdata").get_result();
	auto patchguardvalue_addr = patchguardvalue_sig.as<uint64_t*>(); 
	return (uint64_t)patchguardvalue_addr - (uint64_t)patchguardvalue_sig.get_base<uint64_t*>();    
}