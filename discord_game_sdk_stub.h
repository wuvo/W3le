#ifndef DISCORD_GAME_SDK_STUB_H
#define DISCORD_GAME_SDK_STUB_H

#include "discord_register.h"  // old legacy includes for actual implementation
#include "discord_rpc.h"       // used internally to emulate
#include <cstring>
#include <functional>
#include <memory>
#include <string>

namespace discord {

enum class Result {
    Ok,
    Error,
};

struct Button {
    std::string label;
    std::string url;
    void SetLabel(const char* l) { label = l ? l : ""; }
    void SetUrl(const char* u) { url = u ? u : ""; }
};

struct ActivityAssets {
    std::string largeImage;
    std::string largeText;
    void SetLargeImage(const char* key) { largeImage = key ? key : ""; }
    void SetLargeText(const char* text) { largeText = text ? text : ""; }
};

struct ActivityTimestamps {
    int64_t start = 0;
    void SetStart(int64_t ts) { start = ts; }
};

struct Activity {
    std::string state;
    std::string details;
    ActivityAssets assets;
    ActivityTimestamps timestamps;
    Button buttons[2];
    void SetState(const char* s) { state = s ? s : ""; }
    void SetDetails(const char* d) { details = d ? d : ""; }
    ActivityAssets& GetAssets() { return assets; }
    ActivityTimestamps& GetTimestamps() { return timestamps; }
    Button* GetButtons() { return buttons; }
};

class ActivityManager {
public:
    Result UpdateActivity(const Activity& act, std::function<void(Result)> cb) {
        DiscordRichPresence p{};
        memset(&p, 0, sizeof(p));
        p.state = act.state.c_str();
        p.details = act.details.c_str();
        p.startTimestamp = act.timestamps.start;
        p.largeImageKey = act.assets.largeImage.c_str();
        p.largeImageText = act.assets.largeText.c_str();
        p.button1_label = act.buttons[0].label.c_str();
        p.button1_url = act.buttons[0].url.c_str();
        p.button2_label = act.buttons[1].label.c_str();
        p.button2_url = act.buttons[1].url.c_str();
        Discord_UpdatePresence(&p);
        if (cb) cb(Result::Ok);
        return Result::Ok;
    }
};

class Core {
    ActivityManager activity_manager_{};
public:
    static Result Create(int64_t client_id, uint64_t /*flags*/, std::unique_ptr<Core>* out) {
        DiscordEventHandlers handlers{};
        Discord_Initialize(std::to_string(client_id).c_str(), &handlers, 1, nullptr);
        out->reset(new Core());
        return Result::Ok;
    }

    ActivityManager& ActivityManager() { return activity_manager_; }
    void RunCallbacks() { Discord_RunCallbacks(); }
    void Shutdown() { Discord_Shutdown(); }
};

} // namespace discord

#endif // DISCORD_GAME_SDK_STUB_H
