#pragma once
#include "utils.hpp"
#define GFX_MANAGER     0x28C6F30
#define CAMERA_MANAGER  0xB8
#define CAMERA_FOV      0x18

namespace rust
{
    void set_fov(HANDLE proc_handle, float fov_value)
    {
        const auto asm_base = utils::get_module_base(proc_handle, L"GameAssembly.dll");

        if (!asm_base)
            return;

        const auto gfx_manager = bedaisy::read<std::uintptr_t>(
            proc_handle, asm_base + GFX_MANAGER);

        if (!gfx_manager)
            return;

        const auto camera_manager = bedaisy::read<std::uintptr_t>(
            proc_handle, gfx_manager + CAMERA_MANAGER);

        if (!camera_manager)
            return;

        bedaisy::write<float>(proc_handle, camera_manager + CAMERA_FOV, fov_value);
    }
}