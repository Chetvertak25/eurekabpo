#include <napi.h>
#include <windows.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")

Napi::String GetPrivilege(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
  }

  Napi::String userName = info[0].As<Napi::String>();
  LPUSER_INFO_1 pBuf = NULL;
  DWORD dwLevel = 1;
  NET_API_STATUS nStatus;

  nStatus = NetUserGetInfo(NULL, userName.Utf8Value().c_str(), dwLevel, (LPBYTE*)&pBuf);

  if (nStatus == NERR_Success) {
    std::string privilege;
    switch(pBuf->usri1_priv) {
      case USER_PRIV_ADMIN: privilege = "Администратор"; break;
      case USER_PRIV_USER: privilege = "Пользователь"; break;
      case USER_PRIV_GUEST: privilege = "Гость"; break;
      default: privilege = "Неизвестно"; break;
    }

    if (pBuf != NULL) {
      NetApiBufferFree(pBuf);
    }
    return Napi::String::New(env, privilege);
  } else {
    return Napi::String::New(env, "Пользователя нет");
  }
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("getPrivilege", Napi::Function::New(env, GetPrivilege));
  return exports;
}

NODE_API_MODULE(check_privilege, Init)
