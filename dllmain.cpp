#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <Psapi.h>
#include <unknwn.h>
#include <winnt.h>

#include <functional>
#include <string>
#include <vector>

#include "Pattern16/include/Pattern16.h"
#include "hash.h"

// Utilities

static HRESULT(WINAPI* OrigDirectInput8Create)(
    HINSTANCE hinst,
    DWORD dwVersion,
    REFIID riidltf,
    LPVOID* ppvOut,
    LPUNKNOWN punkOuter
    );

extern "C" __declspec(dllexport) HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst,
    DWORD dwVersion,
    REFIID riidltf,
    LPVOID* ppvOut,
    LPUNKNOWN punkOuter
)
{
    return OrigDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
}

static BOOL LoadDinput8() {
    char lib_path[MAX_PATH];
    GetSystemDirectoryA(lib_path, MAX_PATH);
    strcat_s(lib_path, "\\dinput8.dll");
    auto lib = LoadLibraryA(lib_path);
    if (!lib)
    {
        return FALSE;
    }
    *(void**)&OrigDirectInput8Create = (void*)GetProcAddress(lib, "DirectInput8Create");
    return TRUE;
}

static void initFail(const std::string& err) {
    const char* initTitle = "Failed to initialize DS1HeapPatch.dll";
    MessageBoxA(NULL, err.c_str(), initTitle, MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
    // Can catch this at top level, but this generally does the right thing (crash or defer to mod loader).
    throw std::runtime_error(err);
}

static void* text = nullptr;
static size_t textSize;

static bool initializeText()
{
    static bool textInit = false;
    static MODULEINFO mInfo = {};

    if (textInit) return text != nullptr;
    textInit = true;
    void* pHandle = GetCurrentProcess();
    HMODULE mod = GetModuleHandleA(NULL);
    GetModuleInformation(pHandle, mod, &mInfo, sizeof(mInfo));

    // This can be parsed structurally, especially to find multiple .text sections, but this basically works for fromsoft games.
    std::string dottext = "2E 74 65 78 74";
    uint8_t* result = (uint8_t*)Pattern16::scan(mInfo.lpBaseOfDll, mInfo.SizeOfImage, dottext);
    if (!result) return false;

    textSize = *reinterpret_cast<uint32_t*>(result + 0x10);
    text = result + *reinterpret_cast<uint32_t*>(result + 0x14);
    return true;
}

static void *requirePattern(const std::string& pattern) {
    void* addr = nullptr;
    if (initializeText()) {
        addr = Pattern16::scan(text, textSize, pattern);
    }
    if (!addr) {
        std::ostringstream err;
        err << "Could not find required pattern " << pattern << ". Only Dark Souls Remastered 1.03.1 from Steam is supported. Contact thefifthmatt for issues.";
        std::string errStr = err.str();
        initFail(errStr);
    }
    return addr;
}

template <typename T1, typename F> static bool write(T1* address, int size, F&& fun) {
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    fun();
    return VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
}
template <typename T1, typename T2> static bool write(T1* address, T2 value) {
    return write(address, sizeof(T2), [&] {
        *reinterpret_cast<T2*>(address) = value;
        });
}
// The least safe version
template <typename T1, typename T2> static bool write(T1* address, T2* value, int size) {
    return write(address, size, [&] {
        memcpy(address, value, size);
        });
}

// Patches

static bool patchDS1() {
    bool res = true;
    uint8_t patch[] = { 0x39, 0xC0 };
    for (auto patch_loc : game_hash_compare_checks)
    {
        res &= write((void*)(patch_loc + 3), patch, sizeof(patch));
    }
    uint8_t patch_2[] = { 0xB9, 0x00, 0x00, 0x00, 0x00 };
    for (auto patch_loc : game_hash_compare_checks_alt)
    {
        res &= write((void*)(patch_loc), patch_2, sizeof(patch_2));
    }
    uint8_t patch_nop[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    for (auto patch_loc : game_runtime_hash_checks)
    {
        res &= write((void*)std::get<0>(patch_loc), patch_nop, std::get<1>(patch_loc));
    }
    return res;
}

// TODO: Locate surrounding code rather than heap amount itself
static uint8_t* ffxHeapCode = nullptr;
static std::string ffxHeapScan = "b9 00 00 32 01";
static std::vector<int> ffxHeapOffsets{ 1, 0x26 + 2, 0x6C + 2 };
static int ffxSize = 0x02'32'00'00;

static uint8_t* luaHeapCode = nullptr;
static std::string luaHeapScan = "b9 00 00 38 00";
static std::vector<int> luaHeapOffsets{ 1, 0x26 + 2, 0x68 + 2 };
static int luaSize = 0x9C'40'00;

static int edits = 0;
static int failures = 0;
static void record(bool result) {
    edits++;
    if (!result) {
        failures++;
    }
}

static void onAttach() {
    ffxHeapCode = (uint8_t*)requirePattern(ffxHeapScan);
    luaHeapCode = (uint8_t*)requirePattern(luaHeapScan);

    record(patchDS1());
    for (int offset : luaHeapOffsets) {
        int size = *reinterpret_cast<int32_t*>(luaHeapCode + offset);
        record(write(luaHeapCode + offset, luaSize));
    }
    for (int offset : ffxHeapOffsets) {
        int size = *reinterpret_cast<int32_t*>(ffxHeapCode + offset);
        record(write(ffxHeapCode + offset, ffxSize));
    }

    if (failures > 0) {
        std::ostringstream err;
        err << "Failed to patch memory for DS1HeapPatch.dll (" << failures << " failures out of " << edits << " edits)";
        std::string errStr = err.str();
        initFail(errStr);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (!LoadDinput8()) return FALSE;
        onAttach();
    }
    return TRUE;
}
