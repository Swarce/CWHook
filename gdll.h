#pragma once

/*

 *(_DWORD *)(baseAddress + 0xA8609C8) = 1;
  if ( !(_BYTE)`guard variable for'MainThread(void *)::Cbuf_AddText
    && _cxa_guard_acquire(&`guard variable for'MainThread(void *)::Cbuf_AddText) )
  {
    MainThread(void *)::Cbuf_AddText = (__int64 (__fastcall *)(_QWORD, _QWORD))(baseAddress + 0x16F3A10);
    _cxa_guard_release(&`guard variable for'MainThread(void *)::Cbuf_AddText);
  }
  if ( !(_BYTE)`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt
    && _cxa_guard_acquire(&`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt) )
  {
    MainThread(void *)::LiveStorage_ParseKeysTxt = (__int64 (__fastcall *)(_QWORD))(baseAddress + 0x1011720);
    _cxa_guard_release(&`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt);
  }
  if ( !(_BYTE)`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt2
    && _cxa_guard_acquire(&`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt2) )
  {
    MainThread(void *)::LiveStorage_ParseKeysTxt2 = (__int64 (__fastcall *)(_QWORD))(baseAddress + 0x1012900);
    _cxa_guard_release(&`guard variable for'MainThread(void *)::LiveStorage_ParseKeysTxt2);
  }
  if ( !(_BYTE)`guard variable for'MainThread(void *)::SetScreen )
  {
    if ( _cxa_guard_acquire(&`guard variable for'MainThread(void *)::SetScreen) )
    {
      MainThread(void *)::SetScreen = (__int64 (__fastcall *)(_QWORD))(baseAddress + 0x105D9C0);
      _cxa_guard_release(&`guard variable for'MainThread(void *)::SetScreen);
    }
  }
  MainThread(void *)::SetScreen(10i64);
  MainThread(void *)::LiveStorage_ParseKeysTxt(
    "mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
    "zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
    "wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
    "cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
  MainThread(void *)::LiveStorage_ParseKeysTxt2(
    "mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
    "zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
    "wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
    "cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
  MainThread(void *)::Cbuf_AddText(0i64, "disconnect");

*/

/*
LiveStorage_ParseKeysTxt(
    "mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
    "zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
    "wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
    "cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
LiveStorage_ParseKeysTxt2(
    "mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
    "zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
    "wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
    "cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
*/

/*
lobbybasesetnetworkmode 40 53 48 83 EC 20 8B D9 89 0D ? ? ? ? E8 ? ? ? ? 8B CB E8 ? ? ? ? 8B C8 48 83 C4 20 5B E9 ? ? ? ? SET TO 1
setscreen 8B 05 ? ? ? ? 3B C3 0F 45 C3 89 05 ? ? ? ? E8 ? ? ? ? 4C 8D 35 ? ? ? ? 4C 89 75 D7 SET TO 11
sessionstate 8B 15 ? ? ? ? 4C 8D 05 ? ? ? ? C1 E2 1C 49 8B C0 C1 FA 1C 33 C9 SET TO 0 FOR ZOMBIES OR 1 FOR MP
config1 0F 11 05 ? ? ? ? E8 ? ? ? ? 4C 8D 35 ? ? ? ? 48 89 05 ? ? ? ? 49 8B CE C6 05 ? ? ? ? ? 33 D2 41 B8 ? ? ? ? SET TO 1
config2 48 83 EC 28 80 3D ? ? ? ? ? 75 58 33 C9 SET TO 1
cbuf 63 6C 65 61 72 4B 65 79 53 74 61 74 65 73 0A 00 71 75 69 74 0A 00 00 00 4D 53 57 48 45 45 4C 5F 52 4F 4C 4C 4D 53 47 00 43 00 6F 00 44 00 42 00 6C 00 CALL DISCONNECT

FindAddress("AddCmdBaseDrawText", "48 89 6C 24 ? 41 54 41 56 41 57 48 83 EC 40 80 39 00 4D 8B F8 44 8B B4 24 ? ? ? ? 44 8B E2 0F 29 7C 24 ? 48 8B E9");
FindAddress("AddLobbyBot", "48 83 EC 38 8B 44 24 60 48 C7 44 24 ? ? ? ? ? 89 44 24 20 E8 ? ? ? ? 33 C0 48 83 C4 38 C3");
FindAddress("AddThumbnail", "40 53 48 83 EC 30 48 8B 44 24 ? 4D 8B D1 44 8B 4C 24 ? 45 8B D8 8B CA 48 89 44 24 ? 4D 8B C2 41 8B D3 E8 ? ? ? ? 33 C0 48 83 C4 30 5B C3");
FindAddress("Add_Ammo", "40 53 55 56 41 54 41 55 41 56 41 57 48 83 EC 30 48 8B A9 ? ? ? ? 48 8D 05 ? ? ? ?");
FindAddress("AdvertiseErrorShutdown", "40 53 48 83 EC 20 8B DA E8 ? ? ? ? 8B C8 E8 ? ? ? ? 84 C0 74 11");
FindAddress("AdvertiseLobby", "48 83 EC 28 8B C2 41 83 F8 01 75 10 45 0F B6 C1 BA ? ? ? ? 8B C8 E8 ? ? ? ?");
FindAddress("AngleVectors", "48 8B C4 48 89 58 20 55 56 57 48 83 EC 70 F3 0F 10 41 ? 49 8B F0");
FindAddress("ApplyKnockBack", "4C 89 4C 24 ? 4C 89 44 24 ? 89 54 24 10 48 89 4C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ?");
FindAddress("BG_AddAmmoToClip", "48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 41 8B F8 48 8B CA E8 ? ? ? ? 45 33 C0 48 8D 53 70");
FindAddress("BG_AddAmmoToPool", "40 53 48 83 EC 20 41 8B D8 E8 ? ? ? ? 48 85 C0 74 11 01 58 04");
FindAddress("BG_AddEntityStateEvent", "E8 ? ? ? ? 8B 05 ? ? ? ? 89 83 ? ? ? ? 8B 05 ? ? ? ? 89 83 ? ? ? ? 48 83 C4 20 5B C3");
FindAddress("BG_AddUnpredictableEventToPlayerstate", "E8 ? ? ? ? EB 0F 44 8B 0D ? ? ? ? 4C 8B C3 E8 ? ? ? ?");
FindAddress("BG_AdjustPositionForMover", "48 8B C4 48 89 58 08 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 78 B8 44 0F 29 40 ?");
FindAddress("BG_AnimScriptEvent", "48 83 EC 48 8B 44 24 78 89 44 24 38 48 8B 44 24 ? 48 89 44 24 ? 44 88 4C 24 ? 44 8B CA 48 8B 15 ? ? ? ? 44 88 44 24 ? 45 33 C0 E8 ? ? ? ? 48 83 C4 48 C3");
FindAddress("BG_AnimSelectorTable_GetAnimationTableIndex", "48 89 5C 24 ? 48 BB ? ? ? ? ? ? ? ? 41 C7 00 ? ? ? ? 4D 8B D8 48 23 D3 74 3C 4C 8B 81 ? ? ? ? 45 33 C9 49 63 40 10 85 C0");
FindAddress("BG_AreAttachmentsCompatible", "44 8B C2 44 8B C9 83 F9 3F 0F 87 ? ? ? ? 41 83 F8 3F 77 7D 85 C9 74 76 85 D2 74 72 41 83 F9 29");
FindAddress("BG_Arena_GetMaxPoints", "E8 ? ? ? ? 8B D0 8B 8C 24 ? ? ? ? E8 ? ? ? ? 89 84 24 ? ? ? ?");
FindAddress("BG_Cache_GetEventStringIndex", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 54 24 ? 56 57 41 56 48 83 EC 30 0F B6 D9 48 8D 2D ? ? ? ?");
FindAddress("BG_Cache_GetServerFxNameForIndex", "44 8B C2 44 0F B6 C9 41 0F BA F0 ? 4C 8D 15 ? ? ? ? 80 F9 1C 44 0F 45 C2 45 85 C0 75 17");
FindAddress("BG_ExecuteClientFieldCallbacks", "48 89 5C 24 ? 57 41 54 41 57 48 83 EC 50 8B 15 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 41 BF ? ? ? ?");
FindAddress("BG_GadgetAttachment_IsPowerBasedGadget", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B F9 48 8B D9 81 E7 ? ? ? ? E8 ? ? ? ? 48 8D 35 ? ? ? ?");
FindAddress("BG_GadgetPower_GiveAmmo", "48 89 5C 24 ? 48 89 6C 24 ? 56 41 56 41 57 48 83 EC 20 41 8B F1 45 8B F8 48 8B DA 48 8B E9");
FindAddress("BG_GetAmmoInClip", "48 89 5C 24 ? 57 48 83 EC 20 48 8B F9 48 8B DA 48 8B CA E8 ? ? ? ? 84 C0 74 38 48 8B CB E8 ? ? ? ? 48 8B D0");
FindAddress("BG_GetAmmoNotInClip", "E8 ? ? ? ? 85 C0 75 61 8B 46 28 25 ? ? ? ? 48 8D 0D ? ? ? ? 48 8B 84 C1 ? ? ? ? 48 8B 90 ? ? ? ?");
FindAddress("BG_GetAttachmentGroup", "E8 ? ? ? ? 83 F8 01 8B 45 C7 0F 94 45 87 41 0B 46 44 89 45 C7 8B 45 CB");
FindAddress("BG_GetAttachmentName", "83 F9 3F 77 17 48 63 C1 48 8D 0D ? ? ? ? 48 8B 04 C1 48 85 C0 74 04 48 8B 00 C3");
FindAddress("BG_GetCharacterCustomizationTableForSessionMode", "E8 ? ? ? ? 48 89 44 24 ? 48 85 C0 0F 84 ? ? ? ? 8B 4C 24 40");
FindAddress("BG_GetClientFieldSetFromSetName", "E8 ? ? ? ? 33 DB 8B F0 85 ED 0F 8E ? ? ? ?");
FindAddress("BG_GetClientFieldVersion", "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 4C 89 74 24 ? 41 57 48 83 EC 20 3B 0D ? ? ? ? 8B F2 41 BE ? ? ? ? 41 BF ? ? ? ?");
FindAddress("BG_GetClipSize", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 20 48 8B FA 4C 8B E9 48 85 D2 0F 84 ? ? ? ? 48 8B C2");
FindAddress("BG_GetFireTime", "48 89 5C 24 ? 57 48 83 EC 70 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B C1 48 8D 3D ? ? ? ? 25 ? ? ? ? 8B DA 48 8D 54 24 ? 48 8B 3C C7 E8 ? ? ? ?");
FindAddress("BG_GetHeldWeaponSlot", "48 89 5C 24 ? 45 33 D2 45 0F B6 D8 45 8B CA 48 83 C1 70 48 BB ? ? ? ? ? ? ? ? 0F 1F 00");
FindAddress("BG_GetHipSpreadScale", "40 53 55 56 57 41 56 48 83 EC 70 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B C2 48 8B E9");
FindAddress("BG_GetMaxDamageScaled", "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8D 54 24 ? 48 8B D9 E8 ? ? ? ?");

FindAddress("MSG_Init", "E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? E8 ? ? ? ? 48 63 D0 48 8D 4C 24 ? E8 ? ? ? ? 8B CD");

FindAddress("G_AddEvent", "40 53 48 83 EC 20 49 8B C0 44 8B D2 4C 8B 81 ? ? ? ? 48 8B D9 48 8B D0 41 8B CA 4D 85 C0 74 07 E8 ? ? ? ? EB 0F");
FindAddress("AxisCopy", "0F 10 01 0F 11 02 0F 10 49 10 0F 11 4A 10 0F 10 41 20 0F 11 42 20 C3");
FindAddress("AimAssist_Setup", "E8 ? ? ? ? B1 01 E8 ? ? ? ? 48 83 BB ? ? ? ? ? 74 A9 80 BB ? ? ? ? ? 0F 84 ? ? ? ?");
FindAddress("CG_TransitionSnapshot", "E8 ? ? ? ? 48 8D 93 ? ? ? ? 41 8B CF E8 ? ? ? ? B1 01 E8 ? ? ? ? 48 83 BB ? ? ? ? ? 74 A9 80 BB ? ? ? ? ?");
FindAddress("CG_SetNextSnap", "E8 ? ? ? ? 41 8B CF E8 ? ? ? ? 48 8D 93 ? ? ? ? 41 8B CF E8 ? ? ? ? B1 01 E8 ? ? ? ? 48 83 BB ? ? ? ? ? 74 A9 80 BB ? ? ? ? ? 0F 84 ? ? ? ? 41 8B CF");
FindAddress("CG_SetInitialSnapshot", "E8 ? ? ? ? 48 8B D7 41 8B CF E8 ? ? ? ? 41 8B CF E8 ? ? ? ? 48 8D 93 ? ? ? ? 41 8B CF E8 ? ? ? ? B1 01 E8 ? ? ? ? 48 83 BB ? ? ? ? ? 74 A9");
FindAddress("CG_ReadNextSnapshot", "E8 ? ? ? ? 48 8B F8 48 85 C0 0F 84 ? ? ? ? F6 00 02 75 34 48 8B D0 41 8B CF E8 ? ? ? ? 48 8B D7 41 8B CF E8 ? ? ? ? 41 8B CF E8 ? ? ? ? 48 8D 93 ? ? ? ? 41 8B CF E8 ? ? ? ? B1 01 E8 ? ? ? ? 48 83 BB ? ? ? ? ?");
FindAddress("BG_GetNumWeapons", "E8 ? ? ? ? 83 F8 01 76 0A E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 84 C0 74 0A E8 ? ? ? ? 44 8B E0 EB 03");
*/