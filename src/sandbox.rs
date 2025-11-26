use anyhow::{Context, Result};
use unicorn_engine::unicorn_const::{Arch, MemType, Mode, Permission};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::FirmwareModule;

/// Simple emulator-backed sandbox that executes UEFI PE modules in a constrained pre-boot context.
///
/// The sandbox is intentionally lightweight: it maps the module at its reported image base,
/// allocates scratch stack space, and instruments memory writes to sensitive regions such as
/// SMRAM or a mocked EFI_BOOT_SERVICES table. It is **not** a full UEFI implementation, but it
/// is good enough to surface obviously malicious behaviors like SMM tampering or boot service
/// hook attempts without requiring hashes to change.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum number of instructions to execute before halting.
    pub instruction_limit: u64,
    /// Size of the emulated stack region in bytes.
    pub stack_size: u64,
    /// Address range treated as SMRAM; writes are flagged.
    pub smm_region: (u64, u64),
    /// Address range that mocks EFI_BOOT_SERVICES; writes are flagged.
    pub boot_services_region: (u64, u64),
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            instruction_limit: 100_000,
            stack_size: 256 * 1024,
            smm_region: (0xA0_0000, 0xA1_0000),
            boot_services_region: (0x80_0000_0000, 0x80_0000_8000),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SandboxEventKind {
    SmramWrite,
    BootServiceWrite,
}

#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub kind: SandboxEventKind,
    pub address: u64,
    pub size: usize,
    pub pc: u64,
}

#[derive(Debug, Clone)]
pub struct SandboxReport {
    pub module: FirmwareModule,
    pub executed_instructions: u64,
    pub events: Vec<SandboxEvent>,
    pub notes: Vec<String>,
}

#[derive(Clone)]
struct SandboxState {
    config: SandboxConfig,
    events: Vec<SandboxEvent>,
}

pub fn run_module_sandbox(
    module: &FirmwareModule,
    bytes: &[u8],
    config: &SandboxConfig,
) -> Result<SandboxReport> {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64)?;

    let page_size = 0x1000u64;
    let image_base = module.image_base;
    let image_size = (module.length as u64).max(page_size);
    let image_pages = (image_size + page_size - 1) & !(page_size - 1);

    uc.mem_map(
        image_base,
        image_pages,
        Permission::READ | Permission::EXEC | Permission::WRITE,
    )?;
    uc.mem_write(image_base, bytes)
        .context("failed to write module bytes into emulator")?;

    // Map a scratch stack right after the image to keep the sandbox simple.
    let stack_base = image_base + image_pages;
    let stack_pages = (config.stack_size + page_size - 1) & !(page_size - 1);
    uc.mem_map(
        stack_base,
        stack_pages,
        Permission::READ | Permission::WRITE,
    )?;
    let stack_top = stack_base + stack_pages - 0x10;
    uc.reg_write(RegisterX86::RSP, stack_top)?;

    // Map mock EFI_BOOT_SERVICES so writes do not immediately fault. The hooks let us flag tampering.
    uc.mem_map(
        config.boot_services_region.0,
        config.boot_services_region.1 - config.boot_services_region.0,
        Permission::READ | Permission::WRITE,
    )?;

    // Map a small SMRAM window; contents are irrelevant, but we want to observe writes.
    uc.mem_map(
        config.smm_region.0,
        config.smm_region.1 - config.smm_region.0,
        Permission::READ | Permission::WRITE,
    )?;

    uc.reg_write(RegisterX86::RIP, module.entry_point)?;

    let mut state = SandboxState {
        config: config.clone(),
        events: Vec::new(),
    };
    uc.add_mem_hook(
        MemType::WRITE,
        0,
        u64::MAX,
        |uc, mem_type, address, size, _| {
            let pc: u64 = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
            let mut classify = None;
            let mut state = uc
                .get_data::<SandboxState>()
                .expect("sandbox state present");
            let conf = &state.config;

            if address >= conf.smm_region.0 && address < conf.smm_region.1 {
                classify = Some(SandboxEventKind::SmramWrite);
            } else if address >= conf.boot_services_region.0
                && address < conf.boot_services_region.1
            {
                classify = Some(SandboxEventKind::BootServiceWrite);
            }

            if let Some(kind) = classify {
                state.events.push(SandboxEvent {
                    kind,
                    address,
                    size: size as usize,
                    pc,
                });
                uc.set_data(state).expect("update sandbox state");
            }

            // Let execution continue even if the write is suspicious; the instruction limit will stop it.
            match mem_type {
                MemType::WRITE => true,
                _ => true,
            }
        },
    )?;

    uc.set_data(state);

    let mut executed = 0u64;
    let mut notes = Vec::new();

    let emulation = uc.emu_start(
        module.entry_point,
        image_base + image_pages,
        0,
        config.instruction_limit,
    );

    match emulation {
        Ok(_) => {
            executed = config.instruction_limit;
            notes.push(format!(
                "stopped after executing {} instructions",
                config.instruction_limit
            ));
        }
        Err(err) => {
            notes.push(format!("halted early: {err}"));
        }
    }

    let state = uc
        .get_data::<SandboxState>()
        .unwrap_or_else(|_| SandboxState {
            config: config.clone(),
            events: Vec::new(),
        });
    let events = state.events;

    Ok(SandboxReport {
        module: module.clone(),
        executed_instructions: executed,
        events,
        notes,
    })
}

/// Convenience wrapper to sandbox all discovered modules in a firmware image.
pub fn sandbox_firmware_modules(
    firmware_bytes: &[u8],
    modules: &[FirmwareModule],
    config: &SandboxConfig,
) -> Vec<Result<SandboxReport>> {
    modules
        .iter()
        .map(|module| {
            let start = module.offset as usize;
            let end = start
                .saturating_add(module.length as usize)
                .min(firmware_bytes.len());
            let slice = &firmware_bytes[start..end];
            run_module_sandbox(module, slice, config)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_smram_write_during_execution() {
        // mov rax, 0x1122334455667788; mov [0xa0000], rax; ret
        let code: [u8; 21] = [
            0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0xa3, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3,
        ];

        let module = FirmwareModule {
            offset: 0,
            length: code.len() as u32,
            machine: "x86_64".to_string(),
            subsystem: "test".to_string(),
            characteristics: "0".to_string(),
            entry_point: 0x400000,
            image_base: 0x400000,
            hash: "test".to_string(),
        };

        let config = SandboxConfig {
            instruction_limit: 16,
            ..Default::default()
        };

        let report = run_module_sandbox(&module, &code, &config).expect("sandbox should succeed");
        assert!(
            report
                .events
                .iter()
                .any(|event| matches!(event.kind, SandboxEventKind::SmramWrite))
        );
    }
}
