#include <windows.h>
#include <initguid.h>
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma comment(lib, "dbgeng.lib")

#ifdef _WIN64
#define KDEXT_64BIT
#else
#define KDEXT_32BIT
#endif // _WIN64

#define EXPORT extern "C" __declspec(dllexport)

//#define EXT_TYPE_WDBGEXT

typedef struct
{
    PDEBUG_CLIENT DebugClient;
    PDEBUG_CONTROL DebugControl;
    PDEBUG_SYMBOLS DebugSymbols;
    PDEBUG_REGISTERS DebugRegisters;
    PDEBUG_DATA_SPACES DebugDataSpaces;
    PDEBUG_SYSTEM_OBJECTS DebugSystemObjects;
}DBG_CTX;

DBG_CTX Ctx = { 0 };

VOID
CtxFree()
{
    if (Ctx.DebugClient)
        Ctx.DebugClient->Release();

    if (Ctx.DebugControl)
        Ctx.DebugControl->Release();

    if (Ctx.DebugSymbols)
        Ctx.DebugSymbols->Release();

    if (Ctx.DebugRegisters)
        Ctx.DebugRegisters->Release();

    if (Ctx.DebugDataSpaces)
        Ctx.DebugDataSpaces->Release();

    if (Ctx.DebugSystemObjects)
        Ctx.DebugSystemObjects->Release();
}

HRESULT 
CtxInit()
{
    HRESULT Result = S_OK;

    Result = DebugCreate(IID_IDebugClient, (PVOID*)&Ctx.DebugClient);
    if (Result == S_OK)
    {
        Result = Ctx.DebugClient->QueryInterface(IID_IDebugControl, (PVOID*)&Ctx.DebugControl);
        if (Result == S_OK)
        {
            Result = Ctx.DebugClient->QueryInterface(IID_IDebugSymbols, (PVOID*)&Ctx.DebugSymbols);
            if (Result == S_OK)
            {
                Result = Ctx.DebugClient->QueryInterface(IID_IDebugRegisters, (PVOID*)&Ctx.DebugRegisters);
                if (Result == S_OK)
                {
                    Result = Ctx.DebugClient->QueryInterface(IID_IDebugDataSpaces, (PVOID*)&Ctx.DebugDataSpaces);
                    if (Result == S_OK)
                    {
                        Result = Ctx.DebugClient->QueryInterface(IID_IDebugSystemObjects, (PVOID*)&Ctx.DebugSystemObjects);
                        if (Result == S_OK)
                        {
                            ExtensionApis.nSize = sizeof(ExtensionApis);
                            Result = Ctx.DebugControl->GetWindbgExtensionApis64((PWINDBG_EXTENSION_APIS64)&ExtensionApis);
                            return Result;
                        }
                    }
                }
            }
        }
    }
    CtxFree();
    return Result;
}

#ifdef EXT_TYPE_WDBGEXT
#ifdef _WIN64
EXT_API_VERSION HelperApiVersion = { 3, 5, EXT_API_VERSION_NUMBER64, 0 };
#else
EXT_API_VERSION HelperApiVersion = { 3, 5, EXT_API_VERSION_NUMBER32, 0 };
#endif // _WIN64

WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

EXPORT
LPEXT_API_VERSION
WDBGAPI
ExtensionApiVersion()
{
    return &HelperApiVersion;
}

EXPORT
VOID
WDBGAPI
WinDbgExtensionDllInit(
    _In_ PVOID lpExtensionApis,
    _In_ USHORT MajorVersion,
    _In_ USHORT MinorVersion)
{

    CtxInit();
}
#else

WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

EXPORT
VOID
WDBGAPI
DebugExtensionUninitialize(VOID)
{
    CtxFree();
}

EXPORT
HRESULT
WDBGAPI
DebugExtensionInitialize(
    _Inout_ PULONG Version,
    _Inout_ PULONG Flags
)
{
    return CtxInit();
}
#endif // EXT_TYPE_WDBGEXT

VOID
DecodeDebuggerBlockData()
{
#define BitsCount(val) (sizeof(val) * CHAR_BIT)
#define Shift(val, steps) ((steps) % BitsCount(val))
#define ROL(val, steps)                                                                            \
    (((val) << Shift(val, steps)) | ((val) >> (BitsCount(val) - Shift(val, steps))))
#define BSWAP_64(x)                                                                                \
    (((unsigned __int64)(x) << 56) | (((unsigned __int64)(x) << 40) & 0xff000000000000ULL) |                       \
     (((unsigned __int64)(x) << 24) & 0xff0000000000ULL) | (((unsigned __int64)(x) << 8) & 0xff00000000ULL) |      \
     (((unsigned __int64)(x) >> 8) & 0xff000000ULL) | (((unsigned __int64)(x) >> 24) & 0xff0000ULL) |              \
     (((unsigned __int64)(x) >> 40) & 0xff00ULL) | ((unsigned __int64)(x) >> 56))

    ULONG IsOK = 0;
    ULONG Rdbyte = 0;
    HRESULT Result = S_OK;

    unsigned __int64 KiWaitNever;
    unsigned __int64 KiWaitAlways;
    unsigned __int64 KdpDataBlockEncoded;

    unsigned __int64 KiWaitNeverPtr;
    unsigned __int64 KiWaitAlwaysPtr;
    unsigned __int64 KdpDataBlockEncodedPtr;
    unsigned __int64 KdDebuggerDataBlockPtr;

    unsigned __int64 EncodedChunks[128];//Maybe in new version need large than 1024 byte
    KDDEBUGGER_DATA64 DebuggerData = { 0 };

    Result = Ctx.DebugSymbols->GetOffsetByName("KiWaitNever", &KiWaitNeverPtr);
    Result = Ctx.DebugSymbols->GetOffsetByName("KiWaitAlways", &KiWaitAlwaysPtr);
    Result = Ctx.DebugSymbols->GetOffsetByName("KdpDataBlockEncoded", &KdpDataBlockEncodedPtr);
    Result = Ctx.DebugSymbols->GetOffsetByName("KdDebuggerDataBlock", &KdDebuggerDataBlockPtr);

    KdpDataBlockEncoded = KdpDataBlockEncodedPtr;
    IsOK = ReadMemory(KiWaitNeverPtr, &KiWaitNever, 8, &Rdbyte);
    IsOK = ReadMemory(KiWaitAlwaysPtr, &KiWaitAlways, 8, &Rdbyte);
    IsOK = ReadMemory(KdDebuggerDataBlockPtr, EncodedChunks, sizeof(KDDEBUGGER_DATA64), &Rdbyte);

    unsigned __int64 Nchunks = sizeof(KDDEBUGGER_DATA64) / sizeof(unsigned __int64);
    for (unsigned __int64 i = 0; i < Nchunks; ++i)
    {
        unsigned __int64 decodedChunk = EncodedChunks[i];
        decodedChunk = ROL((decodedChunk ^ KiWaitNever), (KiWaitNever & 0xFF));
        decodedChunk = decodedChunk ^ (KdpDataBlockEncoded | 0xFFFF000000000000ULL);
        decodedChunk = BSWAP_64(decodedChunk);
        decodedChunk = decodedChunk ^ KiWaitAlways;
        (reinterpret_cast<unsigned __int64*>(&DebuggerData))[i] = decodedChunk;
    }

    //WriteMemory(KdDebuggerDataBlockPtr, &DebuggerData, sizeof(DebuggerData), &Rdbyte);
    //SetDebuggerData(&DebuggerData);

    HMODULE dbgeng = GetModuleHandleA("dbgeng.dll");

    //pdb dbgeng.g_Target
    unsigned __int64 g_Target = (unsigned __int64)dbgeng + 0x74DDB8;

    //TargetInfo::ReadKdDataBlock =>memcpy first arg by offset
    unsigned __int64 m_KdDebuggerData = *(unsigned __int64*)g_Target + 0x2F8;

    //KDDEBUGGER_DATA64 Longhorn addition size
    memcpy((void*)m_KdDebuggerData, &DebuggerData, 0x310);
}

EXPORT
HRESULT
WDBGAPI
rox(
	_In_ PDEBUG_CLIENT Client,
	_In_ PCSTR Args
)
{
    HRESULT Result = S_OK;
    DecodeDebuggerBlockData();
    Result = Ctx.DebugControl->Execute(DEBUG_OUTCTL_IGNORE, ".reload", DEBUG_EXECUTE_NOT_LOGGED);
	return Result;
}