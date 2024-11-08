#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <TlHelp32.h>
#include <mmeapi.h>

#include <filesystem>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <intrin.h>
#include <string>
#include <string_view>
#include <iostream>
#include <filesystem>

#include "libs/loadlibrary/Loader.h"
#include "libs/patterns/Hooking.Patterns.h"
#include "libs/minhook/include/MinHook.h"
#include "restorentdll.h"
#include "utils.h"
#include "systemhooks.h"
#include "exceptions.h"
#include "arxan.h"
#include "paths.h"
#include "pluginloader.h"

std::vector<pluginFile> currentLoadedPlugins;

std::string pluginPathString;
std::string loadedPathString;

void directoryWatcher()
{
	std::filesystem::path currentPath = std::filesystem::current_path();
	std::string currentPathString(currentPath.generic_string());

	std::string pluginPathString = currentPathString;
	pluginPathString.append("/plugins");

	std::string loadedPathString = currentPathString;
	loadedPathString.append("/loaded");

	printf("init plugin path %s\n", pluginPathString.c_str());
	printf("init loaded path %s\n", loadedPathString.c_str());
	
	HANDLE file = CreateFile(pluginPathString.c_str(),
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
		NULL);
	assert(file != INVALID_HANDLE_VALUE);
	OVERLAPPED overlapped;
	overlapped.hEvent = CreateEvent(NULL, FALSE, 0, NULL);

	alignas(DWORD) uint8_t change_buf[1024] = { 0 };
	BOOL success = ReadDirectoryChangesW(
		file, change_buf, 1024, TRUE,
		FILE_NOTIFY_CHANGE_LAST_WRITE,
		NULL, &overlapped, NULL);

	while (true) {
		DWORD result = WaitForSingleObject(overlapped.hEvent, 0);

		if (result == WAIT_OBJECT_0) {
			DWORD bytes_transferred;
			GetOverlappedResult(file, &overlapped, &bytes_transferred, FALSE);

			FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)change_buf;

			for (;;) {
				DWORD name_len = event->FileNameLength / sizeof(wchar_t);

				switch (event->Action) {
				case FILE_ACTION_ADDED:
					wprintf(L"Added: %.*s\n", name_len, event->FileName);
					break;
				case FILE_ACTION_REMOVED:
					wprintf(L"Removed: %.*s\n", name_len, event->FileName);
					break;
				case FILE_ACTION_MODIFIED:
				{
					Sleep(500);
					if (wcsstr(event->FileName, L"dll") != nullptr)
					{
						std::wstring name = event->FileName;

						for (int i = 0; i < currentLoadedPlugins.size(); i++)
						{
							if (wcsstr(currentLoadedPlugins[i].filename.generic_wstring().c_str(), name.c_str()) == nullptr)
								continue;

							if (!FreeLibrary(currentLoadedPlugins[i].module))
								printf("couldn't free library within the directoryWatcher\n");

							// https://github.com/paskalian/WID_LoadLibrary
							Sleep(1500);
							UnmapViewOfFile(currentLoadedPlugins[i].module);
							Sleep(500);

							std::string dllPath = pluginPathString;
							dllPath += "//";
							dllPath += currentLoadedPlugins[i].filename.generic_string();
							std::filesystem::path dllFilePath(dllPath);

							std::filesystem::copy(dllFilePath, currentLoadedPlugins[i].filepath, std::filesystem::copy_options::update_existing);

							HMODULE lib = NULL;
							do {
								lib = LoadLibraryA(currentLoadedPlugins[i].filepath.generic_string().c_str());
							} while (lib == NULL);

							PLDR_DATA_TABLE_ENTRY moduleEntry;
							NTSTATUS result = LdrFindEntryForAddress(lib, &moduleEntry);
							moduleEntry->DdagNode->LoadCount = 1;

							currentLoadedPlugins[i].module = lib;
						}
					}

					break;
				}
				case FILE_ACTION_RENAMED_OLD_NAME:
					wprintf(L"Renamed from: %.*s\n", name_len, event->FileName);
					break;
				case FILE_ACTION_RENAMED_NEW_NAME:
					wprintf(L"to: %.*s\n", name_len, event->FileName);
					break;
				default:
					printf("Unknown action!\n");
					break;
				}

				// Are there more events to handle?
				if (event->NextEntryOffset)
					*((uint8_t**)&event) += event->NextEntryOffset;
				else
					break;
			}

			// Queue the next event
			BOOL success = ReadDirectoryChangesW(
				file, change_buf, 1024, TRUE,
				FILE_NOTIFY_CHANGE_LAST_WRITE,
				NULL, &overlapped, NULL);
		}
	}
}

void InitializePluginLoader()
{
	std::filesystem::path currentPath = std::filesystem::current_path();
	std::string currentPathString(currentPath.generic_string());

	std::string pluginPathString = currentPathString;
	pluginPathString.append("/plugins");

	std::string loadedPathString = currentPathString;
	loadedPathString.append("/loaded");

	if (!std::filesystem::is_directory(pluginPathString))
		std::filesystem::create_directory(pluginPathString);

	if (!std::filesystem::is_directory(loadedPathString))
		std::filesystem::create_directory(loadedPathString);

	// clean up loaded plugin folder
	for (const auto& entry : std::filesystem::directory_iterator(loadedPathString))
	{
		auto filePath = entry.path();
		std::filesystem::remove(filePath);
	}

	printf("cleaned up loaded plugins\n");

	// copy plugin folder into the loaded plugins
	for (const auto& entry : std::filesystem::directory_iterator(pluginPathString))
	{
		auto filePath = entry.path();
		if (filePath.string().find(".dll") != std::string::npos)
			std::filesystem::copy(filePath, loadedPathString);
	}

	HMODULE lib = NULL;

	for (const auto& entry : std::filesystem::directory_iterator(loadedPathString))
	{
		auto filePath = entry.path();
		if (filePath.string().find(".dll") != std::string::npos)
		{
			lib = LoadLibraryA(filePath.generic_string().c_str());
			filePath.filename();

			printf("library loaded %llx\n", lib);

			if (!lib)
			{
				printf("couldn't load plugin\n");
				printf("error: %s\n", GetLastErrorAsString().c_str());

				continue;
			}

			// Arxan is setting the loadcount to -1 which only should happen to static linked libraries,
			// ours however is compiled as a dynamic loaded library, this prevents us from being able to unload our library
			// we have to manually modify the loadcount to be 1 to be able to unload it, which isn't a proper fix to the issue
			PLDR_DATA_TABLE_ENTRY moduleEntry;
			NTSTATUS result = LdrFindEntryForAddress(lib, &moduleEntry);
			moduleEntry->DdagNode->LoadCount = 1;

			currentLoadedPlugins.push_back({ filePath.filename(), filePath, lib });
		}
	}
	
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)directoryWatcher, NULL, NULL, NULL);
}