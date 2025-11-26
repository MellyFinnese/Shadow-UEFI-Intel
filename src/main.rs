use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use shadow_uefi_intel::{
    DiffReport, FirmwareScan, SandboxConfig, SandboxEventKind, SandboxReport, build_baseline,
    compare_against_baseline, load_baseline, sandbox_firmware_modules, save_baseline,
    scan_firmware,
};

#[derive(Parser)]
#[command(author, version, about = "Shadow UEFI firmware inspection toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a firmware image and list parsed modules
    Inspect {
        /// Firmware image path
        firmware: PathBuf,
        /// Emit JSON instead of human-readable text
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },
    /// Create a baseline from a firmware image
    Baseline {
        /// Firmware image path
        firmware: PathBuf,
        /// Output baseline JSON path
        #[arg(short, long)]
        output: PathBuf,
        /// Optional label for the baseline
        #[arg(short, long)]
        label: Option<String>,
    },
    /// Compare a firmware image to a saved baseline
    Compare {
        /// Firmware image path
        firmware: PathBuf,
        /// Baseline JSON path
        #[arg(short, long)]
        baseline: PathBuf,
        /// Emit JSON instead of human-readable text
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },
    /// Execute detected PE modules in an emulator sandbox to catch behavioral anomalies
    Sandbox {
        /// Firmware image path
        firmware: PathBuf,
        /// Maximum number of instructions to execute per module
        #[arg(long, default_value_t = 100000)]
        instruction_limit: u64,
    },
}

#[derive(Copy, Clone, ValueEnum, Debug)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { firmware, format } => {
            let scan = scan_firmware(&firmware)?;
            emit_scan(&scan, format);
        }
        Commands::Baseline {
            firmware,
            output,
            label,
        } => {
            let scan = scan_firmware(&firmware)?;
            let baseline = build_baseline(&scan, label.as_deref());
            save_baseline(&output, &baseline)?;
            println!(
                "Baseline '{}' saved to {}",
                baseline.label,
                output.display()
            );
        }
        Commands::Compare {
            firmware,
            baseline,
            format,
        } => {
            let scan = scan_firmware(&firmware)?;
            let baseline = load_baseline(&baseline)?;
            let report = compare_against_baseline(&baseline, &scan);
            emit_report(&report, format);
        }
        Commands::Sandbox {
            firmware,
            instruction_limit,
        } => {
            let bytes = fs::read(&firmware)?;
            let scan = scan_firmware(&firmware)?;
            let config = SandboxConfig {
                instruction_limit,
                ..Default::default()
            };
            let reports = sandbox_firmware_modules(&bytes, &scan.modules, &config);
            emit_sandbox_reports(&reports);
        }
    }

    Ok(())
}

fn emit_scan(scan: &FirmwareScan, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(scan).expect("serializable scan");
            println!("{}", json);
        }
        OutputFormat::Text => {
            println!("Firmware: {}", scan.firmware_path.display());
            println!("SHA256 : {}", scan.firmware_hash);
            if scan.modules.is_empty() {
                println!("No PE/COFF modules were detected in the image.");
                return;
            }

            println!("\nDetected modules ({}):", scan.modules.len());
            for module in &scan.modules {
                println!(
                    "- @0x{offset:08x} len={length:>6} machine={machine} subsystem={subsystem} entry=0x{entry:x} hash={hash}",
                    offset = module.offset,
                    length = module.length,
                    machine = module.machine,
                    subsystem = module.subsystem,
                    entry = module.entry_point,
                    hash = &module.hash[..12]
                );
            }
        }
    }
}

fn emit_report(report: &DiffReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report).expect("serializable report");
            println!("{}", json);
        }
        OutputFormat::Text => {
            println!(
                "Baseline : {} (created {})",
                report.baseline_label, report.baseline_created_at
            );
            println!("Firmware : {}", report.firmware_hash);
            println!("Suspicion score: {}", report.suspicious_score);

            if report.new_modules.is_empty()
                && report.missing_modules.is_empty()
                && report.changed_modules.is_empty()
            {
                println!("\nNo changes detected vs. baseline.");
                return;
            }

            if !report.new_modules.is_empty() {
                println!("\nNew modules ({}):", report.new_modules.len());
                for module in &report.new_modules {
                    println!(
                        "- offset 0x{offset:08x} machine={machine} subsystem={subsystem} hash={hash}",
                        offset = module.offset,
                        machine = module.machine,
                        subsystem = module.subsystem,
                        hash = &module.hash[..12]
                    );
                }
            }

            if !report.missing_modules.is_empty() {
                println!("\nMissing modules ({}):", report.missing_modules.len());
                for module in &report.missing_modules {
                    println!(
                        "- offset 0x{offset:08x} machine={machine} subsystem={subsystem} hash={hash}",
                        offset = module.offset,
                        machine = module.machine,
                        subsystem = module.subsystem,
                        hash = &module.hash[..12]
                    );
                }
            }

            if !report.changed_modules.is_empty() {
                println!("\nChanged modules ({}):", report.changed_modules.len());
                for change in &report.changed_modules {
                    println!(
                        "- baseline 0x{b_off:08x} -> current 0x{c_off:08x} machine={machine} subsystem={subsystem}",
                        b_off = change.baseline.offset,
                        c_off = change.current.offset,
                        machine = change.current.machine,
                        subsystem = change.current.subsystem
                    );
                }
            }
        }
    }
}

fn emit_sandbox_reports(reports: &[Result<SandboxReport>]) {
    if reports.is_empty() {
        println!("No modules found to sandbox.");
        return;
    }

    for result in reports {
        match result {
            Ok(report) => {
                println!(
                    "\nModule @0x{offset:08x} hash={hash}",
                    offset = report.module.offset,
                    hash = &report.module.hash[..12]
                );
                println!("- executed instructions: {}", report.executed_instructions);
                for note in &report.notes {
                    println!("- note: {note}");
                }

                if report.events.is_empty() {
                    println!("- no suspicious memory activity observed");
                } else {
                    for event in &report.events {
                        let label = match event.kind {
                            SandboxEventKind::SmramWrite => "SMRAM write",
                            SandboxEventKind::BootServiceWrite => "BootServices write",
                        };
                        println!(
                            "- {label} at 0x{addr:08x} (size {size} from 0x{pc:08x})",
                            addr = event.address,
                            size = event.size,
                            pc = event.pc
                        );
                    }
                }
            }
            Err(err) => {
                println!("\nModule sandbox failed: {err}");
            }
        }
    }
}
