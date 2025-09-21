#include "TUN.hpp"

bool WintunApi::load()
{
    dll = LoadLibraryW(L"wintun.dll");
    if (!dll)
    {
        return false;
    }
    Open  = (WintunOpenAdapter_t)  GetProcAddress(dll, "WintunOpenAdapter");
    Create= (WintunCreateAdapter_t)GetProcAddress(dll, "WintunCreateAdapter");
    Close = (WintunCloseAdapter_t) GetProcAddress(dll, "WintunCloseAdapter");
    Delete= (WintunDeleteAdapter_t)GetProcAddress(dll, "WintunDeleteAdapter");
    Start = (WintunStartSession_t) GetProcAddress(dll, "WintunStartSession");
    End   = (WintunEndSession_t)   GetProcAddress(dll, "WintunEndSession");
    ReadEvent=(WintunGetReadWaitEvent_t)GetProcAddress(dll, "WintunGetReadWaitEvent");
    Recv  = (WintunReceivePacket_t)GetProcAddress(dll, "WintunReceivePacket");
    RecvRelease=(WintunReleaseReceivePacket_t)GetProcAddress(dll, "WintunReleaseReceivePacket");
    AllocSend=(WintunAllocateSendPacket_t)GetProcAddress(dll, "WintunAllocateSendPacket");
    Send  = (WintunSendPacket_t)  GetProcAddress(dll, "WintunSendPacket");
    GetLuid=(WintunGetAdapterLUID_t)GetProcAddress(dll, "WintunGetAdapterLUID");
    return Open && Create && Close && Start && End && ReadEvent && Recv && RecvRelease && AllocSend && Send && GetLuid;
}

WintunApi::~WintunApi()
{
    if (dll)
    {
        FreeLibrary(dll);
    }
}
