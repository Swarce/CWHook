#pragma once
struct pluginFile
{
	std::filesystem::path filename;
	std::filesystem::path filepath;
	HMODULE module;
};

extern std::vector<pluginFile> currentLoadedPlugins;

void InitializePluginLoader();