use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
    version,
    about = "Low-noise, zero-infra PR code reviewer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Review a pull request or local diff
    Review {
        /// Run without publishing comments to GitHub
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate environment, configuration, and connectivity
    Doctor,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Review { dry_run } => {
            tracing::info!(version = guardian_core::VERSION, dry_run, "guardian review");
            println!(
                "Guardian v{} (dry_run={}) - Fase 0 listo.",
                guardian_core::VERSION,
                dry_run
            );
        }
        Commands::Doctor => {
            println!("Guardian v{} doctor: OK", guardian_core::VERSION);
        }
    }
    Ok(())
}
