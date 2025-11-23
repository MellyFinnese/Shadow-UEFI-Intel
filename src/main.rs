mod analyzer;
mod baseline;
mod image;
mod models;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::analyzer::analyze_against_baseline;
use crate::baseline::{collect_images, create_baseline, read_baseline, write_baseline};
use crate::image::summarize_image;
use crate::models::Baseline;

#[derive(Parser)]
#[command(author, version, about = "UEFI / firmware inspection toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a baseline from one or more firmware images or directories
    Baseline {
        /// Output file for the generated baseline JSON
        #[arg(short, long, default_value = "baseline.json")]
        output: PathBuf,
        /// Firmware images or directories containing images
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Analyze firmware images against an existing baseline
    Analyze {
        /// Path to a previously generated baseline JSON
        #[arg(short, long, default_value = "baseline.json")]
        baseline: PathBuf,
        /// Firmware images or directories containing images
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Inspect a firmware image without comparing to a baseline
    Inspect {
        /// Firmware image to inspect
        #[arg(required = true)]
        image: PathBuf,
    },
}

fn print_baseline(baseline: &Baseline) {
    println!("Baseline generated at {}", baseline.created_at);
    for image in &baseline.images {
        println!(
            "- {} (size: {} bytes, hash: {})",
            image.path.display(),
            image.size,
            image.hash
        );
        for module in &image.modules {
            println!(
                "  * module #{:03} offset {:08x} len {:06} hash {}",
                module.index, module.offset, module.length, module.hash
            );
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Baseline { output, paths } => {
            let images = collect_images(&paths)?;
            let baseline = create_baseline(&images)?;
            write_baseline(&baseline, &output)?;
            print_baseline(&baseline);
        }
        Commands::Analyze { baseline, paths } => {
            let baseline = read_baseline(&baseline)?;
            let alerts = analyze_against_baseline(&baseline, &paths)?;

            for alert in alerts {
                println!(
                    "[{label}] {image}: {message}",
                    label = alert.severity.label(),
                    image = alert.image.display(),
                    message = alert.message
                );
            }
        }
        Commands::Inspect { image } => {
            let summary = summarize_image(image)?;
            println!(
                "{} | size: {} bytes | hash: {} | modules: {}",
                summary.path.display(),
                summary.size,
                summary.hash,
                summary.modules.len()
            );
            for module in summary.modules {
                println!(
                    "- module #{:03} offset {:08x} len {:06} hash {}",
                    module.index, module.offset, module.length, module.hash
                );
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:?}");
        std::process::exit(1);
    }
}
