#pragma once
struct pluginFile
{
	std::filesystem::path filename;
	std::filesystem::path filepath;
	HMODULE module;
	bool bOpeningFile;
};

extern std::vector<pluginFile> currentLoadedPlugins;

void InitializePluginLoader();