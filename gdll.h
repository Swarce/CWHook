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