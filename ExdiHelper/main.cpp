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
    PDEBUG_DATA_SPACES3 DebugDataSpaces;
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
                    Result = Ctx.DebugClient->QueryInterface(IID_IDebugDataSpaces3, (PVOID*)&Ctx.DebugDataSpaces);
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
DecodeDebuggerBlockData(
    _In_ LPVOID BlockData,
    _In_ size_t BlockSize
)
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

    unsigned __int64 EncodedChunks[128];    //Maybe in new version need large than 1024 byte
    unsigned __int64 DebuggerData[128];

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
        (reinterpret_cast<unsigned __int64*>(DebuggerData))[i] = decodedChunk;
    }
    memcpy(BlockData, DebuggerData, BlockSize);
}

VOID SearchTargetKdDebuggerDataPtr(
    _In_ PDBGKD_GET_VERSION64 SystemVersion,
    _Inout_ PVOID* KdDebuggerDataPtr
)
{
#define RD(x) (*(unsigned int*)(x))
#define RB(x) (*(unsigned char*)(x))
#define RQ(x) (*(unsigned __int64*)(x))

    unsigned __int64 g_Target = 0;
    unsigned __int64 ReadDebuggerDataPtr = RQ(RQ(Ctx.DebugDataSpaces) + 0x108);
    for (unsigned __int64 i = ReadDebuggerDataPtr; i < ReadDebuggerDataPtr + 0xA0; i++)
    {
        if (RB(i) == 0x48 &&
            RB(i + 1) == 0x83 &&
            RB(i + 2) == 0x3D &&
            RB(i + 7) == 0x00 &&
            RB(i + 8) == 0x75)
        {
            g_Target = i + (int)RD(i + 3) + 8;
            break;
        }

        if (RB(i) == 0x48 &&
            RB(i + 1) == 0x39 &&
            RB(i + 7) == 0x75 &&
            (RB(i + 2) & 0x0D) == 0x0D)
        {
            g_Target = i + (int)RD(i + 3) + 7;
            break;
        }
    }

    if (g_Target)
    {
        dprintf("g_Target search successful [%p] \n", g_Target);
        unsigned __int64 m_KdDebuggerData = 0;
        unsigned __int64 g_TargetInstance = RQ(g_Target);
        for (unsigned __int64 i = g_TargetInstance; i < g_TargetInstance + 0x400; i += sizeof(unsigned __int64))
        {
            if (RQ(i + 0x18) == SystemVersion->KernBase && RQ(i + 0x48) == SystemVersion->PsLoadedModuleList)
            {
                m_KdDebuggerData = i;
                break;
            }
        }
        if (m_KdDebuggerData)
        {
            dprintf("g_Target->m_KdDebuggerData search successful [%p] \n", m_KdDebuggerData);
            *KdDebuggerDataPtr = (PVOID)m_KdDebuggerData;
        }
        else
        {
            dprintf("Failed to search for g_Target->m_KdDebuggerData \n");
        }
    }
    else
    {
        dprintf("Failed to search for g_Target \n");
    }
}

VOID SearchDbgPteBase(
    _Inout_ PVOID* KdDbgPteBasePtr
)
{
#define RD(x) (*(unsigned int*)(x))
#define RB(x) (*(unsigned char*)(x))
#define RQ(x) (*(unsigned __int64*)(x))

    unsigned __int64 DbgPteBasePtr = 0;
    HMODULE kdexts = GetModuleHandleA("kdexts.dll");
    if (kdexts)
    {
        unsigned __int64 DebugExtensionNotify = (unsigned __int64)GetProcAddress(kdexts, "DebugExtensionNotify");
        unsigned __int64 DebugExtensionCanUnload = (unsigned __int64)GetProcAddress(kdexts, "DebugExtensionCanUnload");
        if (!DebugExtensionNotify)
            dprintf("Unknow kdexts version to find DebugExtensionNotify \n");

        if (!DebugExtensionCanUnload)
            dprintf("The version of kdexts is too old to be patched \n");

        if (DebugExtensionNotify && DebugExtensionCanUnload)
        {
            unsigned __int64 PageTableInfoInitializedPtr = 0;
            for (unsigned __int64 i = DebugExtensionNotify; i < DebugExtensionCanUnload; i++)
            {
                if (RB(i) == 0x48 && RB(i + 1) == 0x83 && RB(i + 2) == 0xC4)
                {
                    unsigned __int64 InstructionPosition = i - 7;
                    PageTableInfoInitializedPtr = InstructionPosition + (int)RD(InstructionPosition + 2) + 7;
                    DbgPteBasePtr = PageTableInfoInitializedPtr + 0x20;
                    *KdDbgPteBasePtr = (PVOID)DbgPteBasePtr;
                    break;
                }
            }
        }
    }

    if (DbgPteBasePtr)
        dprintf("DbgPteBasePtr search successful [%p] \n", DbgPteBasePtr);
    else
        dprintf("DbgPteBasePtr to search for g_Target \n");
}

EXPORT
HRESULT
WDBGAPI
roy(
    _In_ PDEBUG_CLIENT Client,
    _In_ PCSTR Args
)
{
#define IS_VALID_DOS_HEADER(dh) (dh->e_magic == IMAGE_DOS_SIGNATURE && (dh->e_lfanew != 0) && (dh->e_lfanew < 0x10000000) && (dh->e_lfanew%16 == 0))

	ULONG IsOK = 0;
	ULONG Index = 0;
	ULONG Rdbyte = 0;
	WORD IdtEntry[8] = { 0 };
    HRESULT Result = S_OK;
    DEBUG_VALUE Value = {0};
    Result = Ctx.DebugRegisters->GetIndexByName("idtr", &Index);
    if (Result == S_OK)
    {
        Result = Ctx.DebugRegisters->GetValue(Index, &Value);
        if (Result == S_OK)
        {
            ReadMemory(Value.I64, IdtEntry, 16, &Rdbyte);

			DWORD64 kiDivide = ((DWORD64)IdtEntry[5] << 48) + ((DWORD64)IdtEntry[4] << 32) + ((DWORD64)IdtEntry[3] << 16) + (DWORD64)IdtEntry[0];
			DWORD64 searchBased = kiDivide & 0xFFFFFFFFFFFF0000;
			IMAGE_DOS_HEADER Header = { 0 };

			for (DWORD64 i = searchBased; i > 0xFFFFF80000000000; i -= 0x10000)
			{
				ReadMemory(i, &Header, sizeof(Header), &Rdbyte);
                if (Header.e_magic == IMAGE_DOS_SIGNATURE &&
                    Header.e_cblp == 0x0090 &&
                    Header.e_cp == 0x0003 &&
                    Header.e_cparhdr == 0x0004 &&
                    Header.e_maxalloc == 0xFFFF &&
                    Header.e_sp == 0x00B8 &&
                    Header.e_lfarlc == 0x0040 &&
                    Header.e_lfanew)
                {
                    dprintf(".......................... \n");
                    dprintf(".......................... \n");
                    dprintf("Found a valid DOS header. \n");
                    dprintf("Maybe it's NtBase. [%p]\n", i);
					break;
				}
			}
		}
	}
    return Result;
}

EXPORT
HRESULT
WDBGAPI
rox(
	_In_ PDEBUG_CLIENT Client,
	_In_ PCSTR Args
)
{
    dprintf(".......................... \n");
    dprintf(".......................... \n");

    HRESULT Result = S_OK;
    DBGKD_GET_VERSION64 SystemVersion = { 0 };
    if (Ioctl(IG_GET_KERNEL_VERSION, &SystemVersion, sizeof(SystemVersion)))
    {
        PVOID DbgEngKdDebuggerDataPtr = NULL;
        SearchTargetKdDebuggerDataPtr(&SystemVersion, &DbgEngKdDebuggerDataPtr);

        size_t BlockSize = 0;
        if (SystemVersion.MinorVersion < 7601)
            BlockSize = 0x330;
        else if (SystemVersion.MinorVersion < 9200)
            BlockSize = 0x33A;
        else if (SystemVersion.MinorVersion < 9600)
            BlockSize = 0x35A;
        else if (SystemVersion.MinorVersion < 10240)
            BlockSize = 0x35E;
        else if (SystemVersion.MinorVersion < 17763)
            BlockSize = 0x368;
        else if (SystemVersion.MinorVersion < 20150)
            BlockSize = 0x37C;
        else
            BlockSize = 0x380;

        dprintf("Target system version [%d] \n", SystemVersion.MinorVersion);
        dprintf("Target KdDebuggerDataSize [%d] \n", BlockSize);

        PKDDEBUGGER_DATA64 BlockData = (PKDDEBUGGER_DATA64)malloc(BlockSize);
        if (BlockData)
        {
            DecodeDebuggerBlockData(BlockData, BlockSize);
            dprintf("Target KdDebuggerData Decode successful \n");
            dprintf("Target KernBase is [%p] \n", BlockData->KernBase);
            if (BlockData->KernBase > 0xFFFF800000000000)
            {
                memcpy(DbgEngKdDebuggerDataPtr, BlockData, BlockSize);
                Result = Ctx.DebugControl->Execute(DEBUG_OUTCTL_IGNORE, ".reload", DEBUG_EXECUTE_NOT_LOGGED);

                if (SystemVersion.MinorVersion >= 10240)// && kdext.version >=10240
                {

                    dprintf("-------------------------------------------------------- \n");

                    dprintf("Target system version is Windows10 or later. \n");
                    dprintf("It maybe need to patch kdexts.pte=>DbgPteBase. \n");

                    PVOID DbgPteBasePtr = NULL;
                    SearchDbgPteBase(&DbgPteBasePtr);
                    if (DbgPteBasePtr)
                    {
                        Result = Ctx.DebugControl->Execute(DEBUG_OUTCTL_IGNORE, "!pte ffff800000000000", DEBUG_EXECUTE_NOT_LOGGED);
                        dprintf("Invalid  PteBase is [%p] \n", *(unsigned __int64*)DbgPteBasePtr);
                        dprintf("Replaced PteBase is [%p] \n", BlockData->PteBase);
                        *(unsigned __int64*)DbgPteBasePtr = BlockData->PteBase;

                        //Result = Ctx.DebugControl->Execute(DEBUG_OUTCTL_IGNORE, ".reload", DEBUG_EXECUTE_ECHO);
                    }
                }
            }
            else
            {
                dprintf("Failed to DecodeDebuggerBlockData \n");
            }
            free(BlockData);
        }
    }
    else
    {
        dprintf("Failed to IG_GET_KERNEL_VERSION \n");
    }
    dprintf(".......................... \n");
    dprintf(".......................... \n");
	return Result;
}