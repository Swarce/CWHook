#pragma once

typedef __int64(__fastcall* CbufAddText_t)(__int64 playerNum, const char* buff);
typedef __int64(__fastcall* SetScreen_t)(__int64 screenNum);
typedef __int64(__fastcall* SessionState_t)(__int64 state);
typedef __int64(__fastcall* LobbyBaseSetNetworkmode_t)(unsigned int networkMode);
typedef __int64(__fastcall* LiveStorage_ParseKeysTxt_t)(const char* key);
typedef __int64(__fastcall* LiveStorage_ParseKeysTxt2_t)(const char* key);

void InitializeGameHooks();
void setGameVariables();