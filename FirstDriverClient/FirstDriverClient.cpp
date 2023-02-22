#include <Windows.h>
#include <stdio.h>
#include "..\FirstDriver\ioctl.h"
#include "..\FirstDriver\Common.h"

int main(int argc, const char* argv[])
{
	// Check for all required args
	if (argc < 2)
	{
		printf("[!] Target PID required\n");
		printf("Action required (-pp | -up)!\n");
		return 1;
	}

	// Open handle and check if successful
	printf("[+] Opening handle to driver...");
	HANDLE hDriver = CreateFile(
		L"\\\\.\\FirstDriver",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[!] %s (%lu)\n", "Failed to open device", GetLastError());
		return 1;
	}
	printf("success!\n");

	// Check which actions should be taken
	if (strcmp(argv[1], "-pp") == 0)
	{
		// Protect process
		printf("[+] Calling DEVICE_PROTECT_PROCESS...");

		TargetProcess target{};
		target.ProcessId = atoi(argv[2]);

		const BOOL success = DeviceIoControl(
			hDriver,
			DEVICE_PROTECT_PROCESS,
			&target,
			sizeof(target),
			nullptr,
			0,
			nullptr,
			nullptr);

		if (success)
		{
			printf("success!\n");
		}
		else
		{
			printf("failed\n");
		}
	}
	else if (strcmp(argv[1], "-up") == 0)
	{
		// Unprotect process
		printf("[+] Calling DEVICE_UNPROTECT_PROCESS...");

		TargetProcess target{};
		target.ProcessId = atoi(argv[2]);

		const BOOL success = DeviceIoControl(
			hDriver,
			DEVICE_UNPROTECT_PROCESS,
			&target,
			sizeof(target),
			nullptr,
			0,
			nullptr,
			nullptr);

		if (success)
		{
			printf("success!\n");
		}
		else
		{
			printf("failed\n");
		}
	}
	else if (strcmp(argv[1], "-t") == 0)
	{
		printf("[+] Calling DEVICE_PROCESS_TOKEN_PRIVILEGE...");

		TargetProcess target{};
		target.ProcessId = atoi(argv[2]);

		const BOOL success = DeviceIoControl(
			hDriver,
			DEVICE_PROCESS_TOKEN_PRIVILEGE,
			&target,
			sizeof(target),
			nullptr,
			0,
			nullptr,
			nullptr);

		if (success)
		{
			printf("success!\n");
		}
		else
		{
			printf("failed\n");
		}
	}
	else if (strcmp(argv[1], "-l") == 0)
	{
		// list callbacks
		CALLBACK_INFORMATION callbacks[64];
		RtlZeroMemory(callbacks, sizeof(callbacks));

		printf("\n[+] Calling ENUM_PROCESS_CALLBACK...");

		DWORD bytesReturned;
		const BOOL success = DeviceIoControl(
			hDriver,
			ENUM_PROCESS_CALLBACKS,
			nullptr,
			0,
			&callbacks,
			sizeof(callbacks),
			&bytesReturned,
			nullptr);

		if (success)
		{
			printf("success!\n");

			const LONG numberOfCallbacks = bytesReturned / sizeof(CALLBACK_INFORMATION);

			for (LONG i = 0; i < numberOfCallbacks; i++)
			{
				if (callbacks[i].Pointer > 0)
				{
					printf("[%ld] 0x%llX (%s)\n", i, callbacks[i].Pointer, callbacks[i].ModuleName);
				}
			}
		}
		else
		{
			printf("failed\n");
		}

		RtlZeroMemory(callbacks, sizeof(callbacks));

		printf("\n[+] Calling ENUM_THREAD_CALLBACK...");

		DWORD thread_bytesReturned;
		const BOOL thread_success = DeviceIoControl(
			hDriver,
			ENUM_THREAD_CALLBACKS,
			nullptr,
			0,
			&callbacks,
			sizeof(callbacks),
			&thread_bytesReturned,
			nullptr);

		if (thread_success)
		{
			printf("success!\n");

			const LONG numberOfThreadCallbacks = thread_bytesReturned / sizeof(CALLBACK_INFORMATION);

			for (LONG i = 0; i < numberOfThreadCallbacks; i++)
			{
				if (callbacks[i].Pointer > 0)
				{
					printf("[%ld] 0x%llX (%s)\n", i, callbacks[i].Pointer, callbacks[i].ModuleName);
				}
			}
		}
		else
		{
			printf("failed\n");
		}

		RtlZeroMemory(callbacks, sizeof(callbacks));

		printf("\n[+] Calling ENUM_IMAGE_NOTIFY...");

		DWORD image_bytes_returned;
		const BOOL image_success = DeviceIoControl(
			hDriver,
			ENUM_LOAD_IMAGE_NOTIFY,
			nullptr,
			0,
			&callbacks,
			sizeof(callbacks),
			&image_bytes_returned,
			nullptr);

		if (image_success)
		{
			printf("success!\n");

			const LONG number_of_image_callbacks = image_bytes_returned / sizeof(CALLBACK_INFORMATION);

			for (LONG i = 0; i < number_of_image_callbacks; i++)
			{
				if (callbacks[i].Pointer > 0)
				{
					printf("[%ld] 0x%llX (%s)\n", i, callbacks[i].Pointer, callbacks[i].ModuleName);
				}
			}
		}
		else
		{
			printf("failed\n");
		}
	}
	else if (strcmp(argv[1], "-r") == 0)
	{
		printf("[+] Calling ZERO_PROCESS_CALLBACK...");

		TargetProcess target{};
		target.ProcessId = atoi(argv[2]);

		const BOOL success = DeviceIoControl(
			hDriver,
			ZERO_PROCESS_CALLBACK,
			&target,
			sizeof(target),
			nullptr,
			0,
			nullptr,
			nullptr);

		if (success)
		{
			printf("success!\n");
		}
		else
		{
			printf("failed\n");
		}
	}

	// Close handle
	printf("\n[+] Closing handle\n");
	CloseHandle(hDriver);
}
