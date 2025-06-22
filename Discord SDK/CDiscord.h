#pragma once
#define WIN32_LEAN_AND_MEAN      
#define _CRT_SECURE_NO_WARNINGS

#include "../discord_game_sdk_stub.h" // new Social SDK wrapper
#include <Windows.h>
#include <thread>

class CDiscord {
public:
	static void Shutdown();
	static void Idle();
	static void Update(std::string state, std::string details);
	static void Init();
};
