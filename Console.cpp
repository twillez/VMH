#include "VirtMemoryHelper.h"
using namespace VirtualHelper;
using namespace std;
VMH zxc;

#define EXE L"SlimeRancher.exe"
#define DLL L"mono-2.0-bdwgc.dll"               

int ProcessId;
HANDLE HandleProcess;
uint32_t ModuleAddress;

int main()
{
    ProcessId = zxc.GetPidByName(EXE);
    HandleProcess = zxc.GetProcessHandle(ProcessId);
    ModuleAddress = zxc.GetModuleAddress(DLL, ProcessId);

    uint32_t dwDHeealth = ModuleAddress + 0x00CEC660;
    vector<uint32_t> dwDHealthPoints = { 0xFD4 };

    uint32_t dwMoney = ModuleAddress + 0x0039EC60;
    vector<uint32_t> dwMoneyPoints = { 0x74, 0xDE8 };

    uint32_t dwStamina = ModuleAddress + 0x0039EC60;
    vector<uint32_t> dwStaminaPoints = { 0x74, 0xDDC };

    uint32_t dwHealth = ModuleAddress + 0x0039EC60;
    vector<uint32_t> dwHealthPoints = { 0x74, 0xDE0 };

    uint32_t DHealthBaseAddr = zxc.OffsetsCalculator(HandleProcess, dwDHeealth, dwDHealthPoints);
    uint32_t MoneyBaseAddr = zxc.OffsetsCalculator(HandleProcess, dwMoney, dwMoneyPoints);
    uint32_t HealthBaseAddr = zxc.OffsetsCalculator(HandleProcess, dwHealth, dwHealthPoints);
    uint32_t StaminaBaseAddr = zxc.OffsetsCalculator(HandleProcess, dwStamina, dwStaminaPoints);

    uint32_t DHealth = zxc.readmem<uint32_t>(HandleProcess, DHealthBaseAddr);
    uint32_t Money = zxc.readmem<uint32_t>(HandleProcess, MoneyBaseAddr);
    uint32_t Stamina = zxc.readmem<uint32_t>(HandleProcess, StaminaBaseAddr);
    uint32_t Health = zxc.readmem<uint32_t>(HandleProcess, HealthBaseAddr);
    
}