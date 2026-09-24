//! Hegota wallet. Public and private balances, FrameTx only, no relayers.

mod accounts;
mod chain;
mod flow;
mod sync_cache;
mod txbuild;
mod ui;
mod wallet;

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use dialoguer::{Password, Select};

use crate::{chain::load_network, flow::App};

#[derive(Parser)]
#[command(
    name = "kohaku-hegota",
    about = "Hegota wallet for public and private ETH",
    version,
    propagate_version = true
)]
struct Cli {
    #[arg(long, global = true)]
    rpc_url: Option<String>,
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    wallet: Option<String>,
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,
    #[arg(long, global = true)]
    non_interactive: bool,
    #[arg(long, global = true, default_value = "devnet")]
    network: String,
    /// Use a direct HTTP connection instead of Tor.
    /// Also set when `DISABLE_TOR=1`.
    #[arg(long, global = true)]
    without_tor: bool,
    #[arg(long, global = true)]
    broadcast: bool,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an encrypted mnemonic wallet.
    CreateWallet {
        name: String,
        #[arg(long)]
        import: bool,
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,
        #[arg(long)]
        long_seed: bool,
    },
    /// List wallet names.
    ListWallets,
    /// Print the CLI version.
    Version,
    /// Download pool events into an unencrypted cache shared by every wallet.
    HydrateLocalCache,
    /// Print the seed phrase.
    RevealSeedPhrase,
    /// Print an EOA key or a smart-account owner key (`a0`).
    ExportPrivateKey { account: String },
    /// Derive and persist the next public address.
    NextFreshAddress {
        #[arg(long)]
        peek: bool,
    },
    /// Public and private ETH, and with --verbose every account and note.
    Balances {
        #[arg(long)]
        verbose: bool,
    },
    /// Send ETH from one account.
    Transfer {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        amount_wei: Option<String>,
        #[arg(long)]
        amount_formatted: Option<String>,
        #[arg(long)]
        amount_max: bool,
    },
    /// One or more calls. EOAs use SENDER frames; deployed smart accounts use executeBatch.
    TransactRaw {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        targets: Option<String>,
        #[arg(long)]
        payloads: Option<String>,
        #[arg(long)]
        values: Option<String>,
    },
    /// Publish the current epoch root from an account that can pay gas.
    PublishRoot {
        #[arg(long)]
        from: Option<String>,
    },
    /// Shield ETH from one account into one private note.
    Shield {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        amount_wei: Option<String>,
        #[arg(long)]
        amount_formatted: Option<String>,
        #[arg(long)]
        amount_max: bool,
    },
    /// Withdraw private ETH. Merges notes when one proof cannot cover the amount.
    Unshield {
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        next: bool,
        #[arg(long)]
        amount_wei: Option<String>,
        #[arg(long)]
        amount_formatted: Option<String>,
        #[arg(long)]
        amount_max: bool,
        /// `target:calldata[:value],...` run from a new or existing smart account.
        #[arg(long)]
        tail_calls: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    kohaku_minimal_shield::set_circuit_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/circuit"));
    let cli = Cli::parse();
    if let Command::CreateWallet {
        name,
        import,
        mnemonic_file,
        long_seed,
    } = &cli.cmd
    {
        return create(&cli, name, *import, mnemonic_file.clone(), *long_seed).await;
    }
    if matches!(cli.cmd, Command::Version) {
        println!("kohaku-hegota {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if matches!(cli.cmd, Command::HydrateLocalCache) {
        let root = wallet::data_root(cli.data_dir.clone());
        let rpc = chain::rpc_url(cli.rpc_url.clone())?;
        let net = load_network(&cli.network)?;
        chain::warn_if_tor_disabled(cli.without_tor, cli.non_interactive);
        return flow::hydrate_local_cache(&root, &net, rpc, cli.non_interactive, cli.without_tor)
            .await;
    }
    if matches!(cli.cmd, Command::ListWallets) {
        let root = wallet::data_root(cli.data_dir);
        let names = wallet::list_wallets(&root)?;
        if cli.non_interactive {
            println!("{}", serde_json::json!({ "wallets": names }));
        } else if names.is_empty() {
            println!("no wallets");
        } else {
            for name in names {
                println!("{name}");
            }
        }
        return Ok(());
    }
    let app = open(&cli).await?;
    match cli.cmd {
        Command::Version => Ok(()),
        Command::RevealSeedPhrase => flow::reveal_seed(&app),
        Command::ExportPrivateKey { account } => flow::export_key(&app, &account).await,
        Command::NextFreshAddress { peek } => {
            let mut app = app;
            flow::next_fresh(&mut app, peek).await
        }
        Command::Balances { verbose } => {
            let mut app = app;
            flow::balances(&mut app, verbose).await
        }
        Command::Transfer {
            from,
            to,
            amount_wei,
            amount_formatted,
            amount_max,
        } => {
            let mut app = app;
            flow::transfer(
                &mut app,
                from,
                to,
                amount_arg(amount_wei, amount_formatted)?,
                amount_max,
            )
            .await
        }
        Command::TransactRaw {
            from,
            targets,
            payloads,
            values,
        } => {
            let mut app = app;
            flow::transact_raw(&mut app, from, targets, payloads, values).await
        }
        Command::PublishRoot { from } => {
            let mut app = app;
            flow::publish_epoch_root(&mut app, from).await
        }
        Command::Shield {
            from,
            amount_wei,
            amount_formatted,
            amount_max,
        } => {
            let mut app = app;
            flow::shield(
                &mut app,
                from,
                amount_arg(amount_wei, amount_formatted)?,
                amount_max,
            )
            .await
        }
        Command::Unshield {
            to,
            next,
            amount_wei,
            amount_formatted,
            amount_max,
            tail_calls,
        } => {
            let mut app = app;
            flow::unshield(
                &mut app,
                to,
                next,
                amount_arg(amount_wei, amount_formatted)?,
                amount_max,
                tail_calls,
            )
            .await
        }
        Command::CreateWallet { .. } | Command::ListWallets | Command::HydrateLocalCache => {
            unreachable!()
        }
    }
}

async fn create(
    cli: &Cli,
    name: &str,
    import: bool,
    mnemonic_file: Option<PathBuf>,
    long_seed: bool,
) -> Result<()> {
    let root = wallet::data_root(cli.data_dir.clone());
    let password = password(cli, true)?;
    if !cli.non_interactive {
        let again = Password::new().with_prompt("Repeat password").interact()?;
        if again != password {
            bail!("passwords did not match");
        }
    }
    let imported = if import {
        Some(if let Some(path) = mnemonic_file {
            wallet::read_password_file(&path)?
        } else if cli.non_interactive {
            bail!("--import needs --mnemonic-file");
        } else {
            Password::new().with_prompt("Mnemonic").interact()?
        })
    } else {
        None
    };
    let found = if let Some(phrase) = imported.as_deref() {
        if !cli.non_interactive {
            println!("scanning public accounts and frame accounts");
        }
        chain::warn_if_tor_disabled(cli.without_tor, cli.non_interactive);
        let rpc = chain::rpc_url(cli.rpc_url.clone())?;
        let provider = chain::http_provider(rpc, cli.without_tor).await?;
        let net = load_network(&cli.network)?;
        Some(accounts::scan_imported(&provider, &net, phrase).await?)
    } else {
        None
    };
    let phrase = wallet::create_wallet(
        &root,
        name,
        &password,
        imported.as_deref(),
        long_seed,
        found.as_ref().map(|(accounts, _)| accounts.clone()),
    )?;
    if cli.non_interactive {
        let mut body = serde_json::json!({ "wallet": name, "mnemonic": phrase });
        if let Some((accounts, smart_scanned)) = &found {
            body["publicIndexes"] = serde_json::json!(accounts.public_indexes);
            body["nextPublic"] = serde_json::json!(accounts.next_public);
            body["smartIndexes"] = serde_json::json!(accounts.smart_indexes);
            body["smartScanned"] = serde_json::json!(smart_scanned);
        }
        println!("{body}");
    } else {
        println!("wallet {name} created. Write this phrase down; it is not shown again.");
        crate::ui::print_box(&phrase);
        if let Some((accounts, smart_scanned)) = &found {
            println!(
                "stored public indexes {}",
                index_span(&accounts.public_indexes)
            );
            if *smart_scanned {
                println!(
                    "stored frame account indexes {}",
                    index_span(&accounts.smart_indexes)
                );
            } else {
                println!("frame accounts were not scanned; this network has no factory");
            }
        }
    }
    Ok(())
}

fn index_span(indexes: &[u32]) -> String {
    match indexes.last() {
        Some(last) => format!("0-{last}"),
        None => "none".into(),
    }
}

async fn open(cli: &Cli) -> Result<App> {
    let root = wallet::data_root(cli.data_dir.clone());
    let name = resolve_wallet(&root, cli.wallet.clone(), cli.non_interactive)?;
    let password = password(cli, false)?;
    let secrets = wallet::load(&root, &name, &password)?;
    let rpc = chain::rpc_url(cli.rpc_url.clone())?;
    chain::warn_if_tor_disabled(cli.without_tor, cli.non_interactive);
    Ok(App {
        non_interactive: cli.non_interactive,
        broadcast_flag: cli.broadcast,
        rpc,
        without_tor: chain::without_tor(cli.without_tor),
        net: load_network(&cli.network)?,
        root,
        name,
        password,
        secrets,
    })
}

fn resolve_wallet(
    root: &std::path::Path,
    flag: Option<String>,
    non_interactive: bool,
) -> Result<String> {
    if let Some(name) = flag {
        return Ok(name);
    }
    let names = wallet::list_wallets(root)?;
    if names.is_empty() {
        bail!("no wallets. Create one with kohaku-hegota create-wallet <name>.");
    }
    if names.len() == 1 {
        return Ok(names[0].clone());
    }
    if non_interactive {
        bail!("--wallet is required");
    }
    let i = Select::new()
        .with_prompt("Select a wallet")
        .items(&names)
        .interact()?;
    Ok(names[i].clone())
}

fn password(cli: &Cli, creating: bool) -> Result<String> {
    if let Some(path) = &cli.password_file {
        return wallet::read_password_file(path);
    }
    if cli.non_interactive {
        bail!("--password-file is required with --non-interactive");
    }
    let prompt = if creating {
        "New wallet password"
    } else {
        "Wallet password"
    };
    Ok(Password::new().with_prompt(prompt).interact()?)
}

fn amount_arg(wei: Option<String>, formatted: Option<String>) -> Result<Option<String>> {
    match (wei, formatted) {
        (Some(_), Some(_)) => bail!("pass only one of --amount-wei and --amount-formatted"),
        (Some(w), None) => Ok(Some(format!("wei:{w}"))),
        (None, Some(f)) => Ok(Some(f)),
        (None, None) => Ok(None),
    }
}
