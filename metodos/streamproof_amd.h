#pragma once
#include <string>

namespace StreamProof
{
    void SetOverlayWindow(void* hwnd);
    void Enable();
    void Disable();
    void Shutdown();
    std::string GetStatus();
}
