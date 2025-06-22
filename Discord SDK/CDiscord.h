#pragma once
#define WIN32_LEAN_AND_MEAN      
#define _CRT_SECURE_NO_WARNINGS

#include "../discord_register.h" //sdk
#include "../discord_rpc.h" // sdk
#include <Windows.h>
#include <thread>
#include <Windows.h> //windows general header

class CDiscord {
public:
	static void Shutdown();
	static void Idle();
	static void Update(std::string state, std::string details);
	static void Init();
};
