#include "CDiscord.h"
#include <chrono>
#include <iostream>

using namespace std;

bool Work = true;

static int64_t eptime = std::chrono::duration_cast<std::chrono::seconds>(
	std::chrono::system_clock::now().time_since_epoch()
).count();

void UpdatePresence(string state, string details)
{
	if (Work)
	{
		try
		{
			DiscordRichPresence discordPresence;
			memset(&discordPresence, 0, sizeof(discordPresence));

			discordPresence.details = details.c_str();
			discordPresence.state = state.c_str();
			discordPresence.startTimestamp = eptime;
			discordPresence.largeImageKey = "ultimate-bg";
			discordPresence.largeImageText = "UltimateConquer best Conquer Private Server";

			// Button support from discord-rpc-buttons
			discordPresence.button1_label = "Visit Website";
			discordPresence.button1_url = "https://ultimate-conquer.com";
			discordPresence.button2_label = "Join Discord";
			discordPresence.button2_url = "https://discord.gg/HD75P4sBsH";

			Discord_UpdatePresence(&discordPresence);
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
		DiscordEventHandlers Handle;
		memset(&Handle, 0, sizeof(Handle));
		Discord_Initialize("1386153907541118976", &Handle, 1, NULL); // App ID
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
		Discord_Shutdown();
	}
}

void CDiscord::Init()
{
	Work = true;
	if (Work)
	{
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Start, NULL, NULL, NULL);
	}
}
