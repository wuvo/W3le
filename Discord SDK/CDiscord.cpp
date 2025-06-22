#include "CDiscord.h"
#include <chrono>
#include <iostream>
#include <memory>

using namespace std;

static bool Work = true;
static std::unique_ptr<discord::Core> CorePtr{};

static int64_t eptime = std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()
).count();

DWORD WINAPI CallbackLoop(LPVOID)
{
    while (Work && CorePtr)
    {
        CorePtr->RunCallbacks();
        Sleep(16);
    }
    return 0;
}

void UpdatePresence(const string& state, const string& details)
{
    if (Work && CorePtr)
    {
        try
        {
            discord::Activity activity{};
            activity.SetDetails(details.c_str());
            activity.SetState(state.c_str());
            activity.GetTimestamps().SetStart(eptime);
            activity.GetAssets().SetLargeImage("ultimate-bg");
            activity.GetAssets().SetLargeText("UltimateConquer best Conquer Private Server");
            activity.GetButtons()[0].SetLabel("Visit Website");
            activity.GetButtons()[0].SetUrl("https://ultimate-conquer.com");
            activity.GetButtons()[1].SetLabel("Join Discord");
            activity.GetButtons()[1].SetUrl("https://discord.gg/HD75P4sBsH");
            CorePtr->ActivityManager().UpdateActivity(activity, nullptr);
        }
        catch (...)
        {
            std::cerr << "[Discord] Failed to update presence.\n";
        }
    }
}

void Start()
{
    if (Work)
    {
        if (discord::Core::Create(1386153907541118976LL, 0, &CorePtr) != discord::Result::Ok)
        {
            std::cerr << "[Discord] Failed to initialize core.\n";
            return;
        }
        CreateThread(NULL, 0, CallbackLoop, NULL, 0, NULL);
        UpdatePresence("Idle", "");
    }
}

void CDiscord::Update(string state, string details)
{
	if (Work)
	{
		UpdatePresence(state, details);
	}
}

void CDiscord::Idle()
{
	if (Work)
	{
		UpdatePresence("Idle", "");
	}
}

void CDiscord::Shutdown()
{
    if (Work)
    {
        Work = false;
        if (CorePtr)
        {
            CorePtr->Shutdown();
            CorePtr.reset();
        }
    }
}

void CDiscord::Init()
{
    Work = true;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);
}
