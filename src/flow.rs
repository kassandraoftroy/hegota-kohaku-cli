//! Command flows. Interactive order matches kohaku-cli: wallet, password, missing args, confirm.

use alloy::{
    primitives::{Address, B256, Bytes, U256, utils::parse_units},
    providers::Provider,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use anyhow::{Context, Result, bail};
use dialoguer::{Confirm, Input, Select};
use kohaku_frametx_kit::{
    FrameTx, FrameTxClient, SETTLE_FRAME_GAS, SETTLE_FRAME_STATE_GAS, SimulateResult,
    recent_root_window_error,
};
use kohaku_kv_store::{Store, file::FileStore};
use kohaku_minimal_shield::{
    Call, Note, PoolProvider, SelectError,
    abis::ShieldedPool,
    indexer::{Indexer, rpc::RpcSyncer, verifier::Verifier},
    plan_unshield,
};
use ruint::aliases::U256 as Ruint;
use serde_json::{Value, json};

use crate::{
    accounts::{self, Eoa, Smart},
    chain::{self, Network},
    sync_cache::{self, Extend, SyncCache},
    txbuild::{self, APPROVE_EXEC, APPROVE_STATE, OutCall},
    wallet::{self, SavedNote, Secrets},
};

pub struct App {
    pub non_interactive: bool,
    pub broadcast_flag: bool,
    pub rpc: reqwest::Url,
    pub without_tor: bool,
    pub net: Network,
    pub root: std::path::PathBuf,
    pub name: String,
    pub password: String,
    pub secrets: Secrets,
}

impl App {
    async fn provider(&self) -> Result<impl Provider + Clone + use<>> {
        chain::http_provider(self.rpc.clone(), self.without_tor).await
    }
}

#[derive(Clone)]
struct Picked {
    label: String,
    address: Address,
    balance: U256,
    eoa: Option<PrivateKeySigner>,
    smart: Option<Smart>,
}

struct Held {
    symbol: String,
    amount: U256,
    decimals: u8,
}

pub async fn balances(app: &mut App, verbose: bool) -> Result<()> {
    let provider = app.provider().await?;
    sync_notes(app, &provider).await?;
    let report = block_sync_progress("syncing public addresses", None);
    let mut done = 0u64;
    let mut total = estimate_public_rpc_steps(app);
    report(0, total.max(1));
    let mut tick = || {
        done += 1;
        if done > total {
            total = done;
        }
        report(done, total.max(1));
    };
    let (eoas, eoa_token_amts) = accounts::load_eoas(
        app.rpc.clone(),
        app.without_tor,
        &app.secrets,
        &app.net.tokens,
        &mut tick,
    )
    .await?;
    let (smart, smart_token_amts) = accounts::load_smart(
        app.rpc.clone(),
        app.without_tor,
        &app.net,
        &app.secrets,
        &app.net.tokens,
        &mut tick,
    )
    .await?;
    let eoa_tokens: Vec<Vec<Held>> = eoa_token_amts
        .into_iter()
        .map(|list| {
            list.into_iter()
                .map(|t| Held {
                    symbol: t.symbol,
                    amount: t.amount,
                    decimals: t.decimals,
                })
                .collect()
        })
        .collect();
    let smart_tokens: Vec<Vec<Held>> = smart_token_amts
        .into_iter()
        .map(|list| {
            list.into_iter()
                .map(|t| Held {
                    symbol: t.symbol,
                    amount: t.amount,
                    decimals: t.decimals,
                })
                .collect()
        })
        .collect();
    let public: U256 = eoas
        .iter()
        .map(|e| e.balance)
        .chain(smart.iter().filter(|s| s.deployed).map(|s| s.balance))
        .fold(U256::ZERO, |a, b| a + b);
    let private = app
        .secrets
        .notes
        .iter()
        .filter(|n| !n.pending)
        .fold(Ruint::ZERO, |a, n| a + n.note.value);
    // Close on real work (no fake snap to an overestimate).
    report(done.max(1), done.max(1));
    if app.non_interactive {
        println!(
            "{}",
            json!({
                "publicWei": public.to_string(),
                "privateWei": private.to_string(),
                "eoas": eoas.iter().zip(&eoa_tokens).map(|(e, tokens)| json!({
                    "index": e.index,
                    "address": format!("{:#x}", e.signer.address()),
                    "wei": e.balance.to_string(),
                    "tokens": token_json(tokens),
                })).collect::<Vec<_>>(),
                "smart": smart.iter().zip(&smart_tokens).map(|(s, tokens)| json!({
                    "index": s.index,
                    "account": format!("{:#x}", s.account),
                    "owner": format!("{:#x}", s.owner.address()),
                    "deployed": s.deployed,
                    "wei": s.balance.to_string(),
                    "tokens": token_json(tokens),
                })).collect::<Vec<_>>(),
                "notes": app.secrets.notes.iter().map(|n| json!({
                    "wei": n.note.value.to_string(),
                    "pending": n.pending,
                    "index": n.index,
                    "commitment": format!("{:#x}", b256(n.note.commitment())),
                })).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    // 1. Aggregated public holdings (ETH + ERC-20s across EOAs / smart accounts).
    crate::ui::print_section("Public holdings");
    let mut public_rows = vec![vec!["ETH".into(), fmt(public)]];
    for token in &app.net.tokens {
        let mut sum = U256::ZERO;
        for held in eoa_tokens.iter().chain(smart_tokens.iter()) {
            for h in held.iter().filter(|h| h.symbol == token.symbol) {
                sum += h.amount;
            }
        }
        if !sum.is_zero() {
            public_rows.push(vec![
                token.symbol.clone(),
                fmt_units(sum, token.decimals),
            ]);
        }
    }
    crate::ui::print_table(&["Asset", "Amount"], &public_rows);

    // 2. Private ETH aggregate.
    crate::ui::print_section("Private holdings");
    crate::ui::print_table(
        &["Asset", "Amount"],
        &[vec!["ETH".into(), fmt_r(private)]],
    );

    if verbose {
        // 3. Address-by-address (ETH labeled).
        for (e, tokens) in eoas.iter().zip(&eoa_tokens) {
            crate::ui::print_section(&format!("EOA {}  {:#x}", e.index, e.signer.address()));
            let mut rows = vec![vec!["ETH".into(), fmt(e.balance)]];
            for h in tokens {
                rows.push(vec![h.symbol.clone(), fmt_units(h.amount, h.decimals)]);
            }
            crate::ui::print_table(&["Asset", "Amount"], &rows);
        }
        for (s, tokens) in smart.iter().zip(&smart_tokens) {
            let title = format!(
                "a{}  {:#x}  (owner {:#x}){}",
                s.index,
                s.account,
                s.owner.address(),
                if s.deployed { "" } else { "  (not deployed)" }
            );
            crate::ui::print_section(&title);
            let mut rows = vec![vec!["ETH".into(), fmt(s.balance)]];
            for h in tokens {
                rows.push(vec![h.symbol.clone(), fmt_units(h.amount, h.decimals)]);
            }
            crate::ui::print_table(&["Asset", "Amount"], &rows);
        }

        // 4. Notes.
        crate::ui::print_section("Notes");
        let note_rows: Vec<Vec<String>> = app
            .secrets
            .notes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                vec![
                    i.to_string(),
                    fmt_r(n.note.value),
                    format!("{:#x}", b256(n.note.commitment())),
                    n.index
                        .map(|j| format!("m/8141'/1'/{j}'"))
                        .unwrap_or_else(|| "—".into()),
                    if n.pending {
                        "pending".into()
                    } else {
                        String::new()
                    },
                ]
            })
            .collect();
        crate::ui::print_table(
            &["#", "Amount", "Commitment", "Path", "Status"],
            &note_rows,
        );

        if app.net.acct_factory.is_zero() {
            println!(
                "\nSmart accounts are hidden until FrameAccountFactory is redeployed (`just deploy-factory`)."
            );
        }
    }
    Ok(())
}

pub async fn next_fresh(app: &mut App, peek: bool) -> Result<()> {
    let index = app.secrets.next_public;
    let signer = wallet::signer_at(&app.secrets.mnemonic, &wallet::eoa_path(index))?;
    if !peek {
        if !app.secrets.public_indexes.contains(&index) {
            app.secrets.public_indexes.push(index);
        }
        app.secrets.next_public = index + 1;
        wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
    }
    let address = format!("{:#x}", signer.address());
    if app.non_interactive {
        println!(
            "{}",
            json!({ "index": index, "address": address, "peek": peek })
        );
    } else {
        println!("{address}");
    }
    Ok(())
}

pub async fn export_key(app: &App, account: &str) -> Result<()> {
    let signer = resolve_key(app, account).await?;
    let key = format!("0x{}", hex::encode(signer.credential().to_bytes()));
    if app.non_interactive {
        println!("{}", json!({ "account": account, "privateKey": key }));
    } else {
        println!("{key}");
    }
    Ok(())
}

pub fn reveal_seed(app: &App) -> Result<()> {
    if !app.non_interactive {
        let ok = Confirm::new()
            .with_prompt("Print the seed phrase?")
            .default(false)
            .interact()?;
        if !ok {
            return Ok(());
        }
    }
    if app.non_interactive {
        println!("{}", json!({ "mnemonic": app.secrets.mnemonic }));
    } else {
        crate::ui::print_box(&app.secrets.mnemonic);
    }
    Ok(())
}

pub async fn transfer(
    app: &mut App,
    from: Option<String>,
    to: Option<String>,
    amount: Option<String>,
    max: bool,
) -> Result<()> {
    let picked = pick_from(app, from.as_deref(), true).await?;
    let dest = pick_to(app, to, true, false).await?;
    let client = chain::frame_client(&app.rpc);
    let (tip, max_fee) = client.fees().await?;
    let reserve = call_cost(
        &client,
        &picked,
        &[OutCall::simple(dest, U256::ZERO)],
        tip,
        max_fee,
    )
    .await?;
    let value = pick_value(app, amount.as_deref(), max, picked.balance, reserve).await?;
    let calls = vec![OutCall::simple(dest, value)];
    commit_calls(
        app,
        &client,
        &picked,
        &calls,
        tip,
        max_fee,
        json!({
            "kind": "transfer",
            "path": path_name(&picked),
            "from": picked.label,
            "to": format!("{dest:#x}"),
            "wei": value.to_string(),
        }),
    )
    .await
}

pub async fn transact_raw(
    app: &mut App,
    from: Option<String>,
    targets: Option<String>,
    payloads: Option<String>,
    values: Option<String>,
) -> Result<()> {
    let picked = pick_from(app, from.as_deref(), true).await?;
    let calls = if let (Some(t), Some(p)) = (targets, payloads) {
        parse_raw(&t, &p, values.as_deref())?
    } else if app.non_interactive {
        bail!("--targets and --payloads are required");
    } else {
        let t: String = Input::new()
            .with_prompt("Targets (comma-separated)")
            .interact_text()?;
        let p: String = Input::new()
            .with_prompt("Payloads (comma-separated hex)")
            .interact_text()?;
        let v: String = Input::new()
            .with_prompt("Values in wei (comma-separated, blank for 0)")
            .allow_empty(true)
            .interact_text()?;
        parse_raw(&t, &p, if v.is_empty() { None } else { Some(&v) })?
    };
    let client = chain::frame_client(&app.rpc);
    let (tip, max_fee) = client.fees().await?;
    let value = calls.iter().fold(U256::ZERO, |a, c| a + c.value);
    commit_calls(
        app,
        &client,
        &picked,
        &calls,
        tip,
        max_fee,
        json!({
            "kind": "transact-raw",
            "path": path_name(&picked),
            "from": picked.label,
            "calls": calls.len(),
            "wei": value.to_string(),
        }),
    )
    .await
}

pub async fn shield(
    app: &mut App,
    from: Option<String>,
    amount: Option<String>,
    max: bool,
) -> Result<()> {
    let picked = pick_from(app, from.as_deref(), true).await?;
    let client = chain::frame_client(&app.rpc);
    let (tip, max_fee) = client.fees().await?;
    let chain = client.chain_id().await?;
    if chain != app.net.chain_id {
        bail!("rpc chain {chain} != profile {}", app.net.chain_id);
    }
    let provider = app.provider().await?;
    let epoch = ShieldedPool::new(app.net.pool, &provider)
        .currentEpoch()
        .call()
        .await?;
    let shield_cost = shield_cost(app, &picked, epoch, chain, tip, max_fee).await?;
    let value = pick_value(app, amount.as_deref(), max, picked.balance, shield_cost).await?;
    let note_index = app.secrets.next_note;
    let note = wallet::note_at(
        &app.secrets.mnemonic,
        note_index,
        to_r(value),
        chain,
        app.net.pool,
    )?;
    let tx = shield_tx(app, &picked, &note, epoch, chain, tip, max_fee).await?;
    ensure_can_pay(picked.balance, tx.max_cost(), value)?;
    let summary = json!({
        "kind": "shield",
        "path": path_name(&picked),
        "from": format!("{:#x}", picked.address),
        "wei": value.to_string(),
        "noteIndex": note_index,
        "commitment": format!("{:#x}", b256(note.commitment())),
        "publishesRoot": true,
    });
    if !want_broadcast(app, &summary)? {
        return Ok(());
    }
    app.secrets.next_note = note_index.saturating_add(1);
    app.secrets.notes.push(SavedNote {
        note: note.clone(),
        pending: true,
        index: Some(note_index),
    });
    wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
    let client = chain::frame_client(&app.rpc);
    if let Err(err) = send_and_wait(&client, &tx).await {
        if !err.to_string().contains("timed out waiting") {
            app.secrets.notes.retain(|n| n.note != note);
            wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
        }
        return Err(err);
    }
    if let Some(saved) = app.secrets.notes.iter_mut().rev().find(|n| n.note == note) {
        saved.pending = false;
    }
    wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
    if app.non_interactive {
        println!("{summary}");
    } else {
        println!("shielded {}", fmt(value));
    }
    Ok(())
}

pub async fn unshield(
    app: &mut App,
    to: Option<String>,
    next: bool,
    amount: Option<String>,
    max: bool,
    tail: Option<String>,
) -> Result<()> {
    let provider = app.provider().await?;
    sync_notes(app, &provider).await?;
    let notes: Vec<Note> = app
        .secrets
        .notes
        .iter()
        .filter(|n| !n.pending)
        .map(|n| n.note.clone())
        .collect();
    let total = notes.iter().fold(Ruint::ZERO, |a, n| a + n.value);
    if total.is_zero() {
        bail!("no unspent private ETH");
    }
    let client = chain::frame_client(&app.rpc);
    let (tip, max_fee) = client.fees().await?;
    let fee_guess = to_r(max_fee * U256::from(8_000_000u64) * U256::from(2u64));
    let want = if max {
        max_withdrawable(&notes, fee_guess)?
    } else if let Some(raw) = amount {
        parse_amount(&raw)?
    } else if app.non_interactive {
        bail!("pass an amount or --amount-max");
    } else {
        let entered: String = Input::new()
            .with_prompt(format!("Amount in ETH (max {})", fmt_r(total)))
            .interact_text()?;
        if entered == "max" {
            max_withdrawable(&notes, fee_guess)?
        } else {
            parse_amount(&entered)?
        }
    };
    let mut rng = rand::rng();
    let plan = plan_unshield(&notes, want, fee_guess, &mut rng).map_err(|e| match e {
        SelectError::Insufficient { .. } => {
            anyhow::anyhow!("notes cannot cover that amount and fees")
        }
        other => anyhow::anyhow!("{other}"),
    })?;
    let tail_calls = if let Some(spec) = tail {
        Some(parse_tail(&spec)?)
    } else if app.non_interactive {
        None
    } else {
        None
    };
    let mut remember_smart: Option<u32> = None;
    let mut remember_public: Option<u32> = None;
    let (recipient, smart_for_tail) = if tail_calls.is_some() {
        let smart = if next {
            accounts::next_free_smart(
                app.rpc.clone(),
                app.without_tor,
                &app.net,
                &app.secrets,
            )
            .await?
        } else {
            match to.as_deref() {
                Some(spec) if spec.starts_with('a') => {
                    let j: u32 = spec[1..].parse().context("smart selector")?;
                    load_one_smart(app, j).await?
                }
                Some(_) => bail!("--tail-calls needs --next or --to aN"),
                None if app.non_interactive => bail!("--tail-calls needs --next or --to aN"),
                None => prompt_tail_account(app).await?,
            }
        };
        remember_smart = Some(smart.index);
        (smart.account, Some(smart))
    } else {
        let dest = if next {
            let index = app.secrets.next_public;
            let signer = wallet::signer_at(&app.secrets.mnemonic, &wallet::eoa_path(index))?;
            remember_public = Some(index);
            signer.address()
        } else {
            pick_to(app, to, true, true).await?
        };
        (dest, None)
    };
    let epoch = ShieldedPool::new(app.net.pool, &provider)
        .currentEpoch()
        .call()
        .await?;
    let mut slot = published_slot(app, &provider, epoch).await?;
    let summary = json!({
        "kind": "unshield",
        "publicWei": want.to_string(),
        "recipient": format!("{recipient:#x}"),
        "account": smart_for_tail.as_ref().map(|s| format!("a{}", s.index)),
        "merges": plan.merges.iter().map(|m| json!({
            "inputWei": [m.inputs[0].value.to_string(), m.inputs[1].value.to_string()],
            "outputWei": m.output.value.to_string(),
        })).collect::<Vec<_>>(),
        "inputs": plan.inputs.len(),
        "changeWei": plan.change.as_ref().map(|n| n.value.to_string()),
        "noteIndex": app.secrets.next_note,
        "rootSlot": slot,
        "tail": tail_calls.is_some(),
        "publishesRoot": !plan.merges.is_empty() || plan.change.is_some(),
    });
    if !want_broadcast(app, &summary)? {
        return Ok(());
    }
    let chain = client.chain_id().await?;
    let mut live: Vec<Note> = notes;
    let mut rng = rand::rng();
    loop {
        let step =
            plan_unshield(&live, want, fee_guess, &mut rng).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(merge) = step.merges.first() {
            let (output, born) = allocate_note(app, &merge.output)?;
            let authorizer = PrivateKeySigner::random();
            let msp = provider_for(app).await?;
            let result = msp
                .join_split(
                    &merge.inputs,
                    Some(&output),
                    Ruint::ZERO,
                    false,
                    Address::ZERO,
                    None,
                    app.net.multicall3,
                    &authorizer,
                    slot,
                    epoch,
                    chain,
                    tip,
                    max_fee,
                )
                .await?;
            if let Some(out) = result.change.clone() {
                remember_born(app, &out, born)?;
            }
            if let Err(err) = send_and_wait(&client, &result.tx).await {
                if !err.to_string().contains("timed out waiting") {
                    app.secrets.notes.retain(|n| n.index != Some(born));
                    wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
                }
                return Err(err);
            }
            live.retain(|n| n != &merge.inputs[0] && n != &merge.inputs[1]);
            let mut born_notes = Vec::new();
            if let Some(out) = result.change.clone() {
                born_notes.push((out.clone(), born));
                live.push(out);
            }
            replace_notes(app, &live, &born_notes)?;
            if result.change.is_some() {
                slot = published_slot(app, &provider, epoch).await?;
            }
            continue;
        }
        let msp = provider_for(app).await?;
        let tail_call = if let (Some(calls), Some(smart)) = (&tail_calls, &smart_for_tail) {
            let (_, tail) = msp
                .prepare_account_tail(
                    &provider,
                    &smart.owner,
                    calls,
                    app.net.multicall3,
                    0,
                    0,
                    chain,
                    true,
                )
                .await?;
            Some(tail)
        } else {
            Some(msp.claim_tail(recipient))
        };
        let (change_template, born) = if max {
            (None, None)
        } else if let Some(change) = step.change.as_ref() {
            let (note, index) = allocate_note(app, change)?;
            (Some(note), Some(index))
        } else {
            let mut placeholder = step.inputs[0].clone();
            placeholder.value = Ruint::ZERO;
            let (note, index) = allocate_note(app, &placeholder)?;
            (Some(note), Some(index))
        };
        let authorizer = PrivateKeySigner::random();
        let result = msp
            .join_split(
                &step.inputs,
                change_template.as_ref(),
                want,
                max,
                recipient,
                tail_call,
                app.net.multicall3,
                &authorizer,
                slot,
                epoch,
                chain,
                tip,
                max_fee,
            )
            .await?;
        if let (Some(change), Some(index)) = (result.change.as_ref(), born) {
            remember_born(app, change, index)?;
        }
        if let Err(err) = send_and_wait(&client, &result.tx).await {
            if !err.to_string().contains("timed out waiting") && born.is_some() {
                app.secrets.notes.retain(|n| n.index != born);
                wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
            }
            return Err(err);
        }
        live.retain(|n| !step.inputs.iter().any(|spent| spent == n));
        let mut born_notes = Vec::new();
        if let Some(change) = result.change {
            if let Some(index) = born {
                born_notes.push((change.clone(), index));
            }
            live.push(change);
        }
        replace_notes(app, &live, &born_notes)?;
        if let Some(index) = remember_smart {
            if !app.secrets.smart_indexes.contains(&index) {
                app.secrets.smart_indexes.push(index);
            }
            wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
        }
        if let Some(index) = remember_public {
            if !app.secrets.public_indexes.contains(&index) {
                app.secrets.public_indexes.push(index);
            }
            if app.secrets.next_public <= index {
                app.secrets.next_public = index + 1;
            }
            wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
        }
        if app.non_interactive {
            println!(
                "{}",
                json!({
                    "publicWei": result.public_amount.to_string(),
                    "feeWei": result.fee.to_string(),
                    "recipient": format!("{recipient:#x}"),
                })
            );
        } else {
            println!(
                "unshielded {} to {recipient:#x}",
                fmt_r(result.public_amount)
            );
        }
        break;
    }
    Ok(())
}

async fn load_one_smart(app: &App, j: u32) -> Result<Smart> {
    accounts::load_one_smart(
        app.rpc.clone(),
        app.without_tor,
        &app.net,
        &app.secrets,
        j,
    )
    .await
}

fn allocate_note(app: &mut App, template: &Note) -> Result<(Note, u32)> {
    let index = app.secrets.next_note;
    let note = wallet::note_at(
        &app.secrets.mnemonic,
        index,
        template.value,
        template.chain_id,
        template.pool,
    )?;
    app.secrets.next_note = index.saturating_add(1);
    Ok((note, index))
}

fn remember_born(app: &mut App, note: &Note, index: u32) -> Result<()> {
    app.secrets.notes.push(SavedNote {
        note: note.clone(),
        pending: true,
        index: Some(index),
    });
    wallet::save(&app.root, &app.name, &app.password, &app.secrets)
}

fn same_secrets(a: &Note, b: &Note) -> bool {
    a.spend_key == b.spend_key && a.rho == b.rho && a.chain_id == b.chain_id && a.pool == b.pool
}

fn replace_notes(app: &mut App, live: &[Note], born: &[(Note, u32)]) -> Result<()> {
    let previous = app.secrets.notes.clone();
    let index_for = |note: &Note| {
        born.iter()
            .find(|(n, _)| same_secrets(n, note))
            .map(|(_, i)| *i)
            .or_else(|| {
                previous
                    .iter()
                    .find(|saved| same_secrets(&saved.note, note))
                    .and_then(|saved| saved.index)
            })
    };
    let pending: Vec<SavedNote> = previous
        .iter()
        .filter(|n| n.pending && !live.iter().any(|note| same_secrets(&n.note, note)))
        .cloned()
        .collect();
    app.secrets.notes = live
        .iter()
        .cloned()
        .map(|note| SavedNote {
            index: index_for(&note),
            note,
            pending: false,
        })
        .chain(pending)
        .collect();
    wallet::save(&app.root, &app.name, &app.password, &app.secrets)
}

pub async fn publish_epoch_root(app: &mut App, from: Option<String>) -> Result<()> {
    let picked = pick_from(app, from.as_deref(), true).await?;
    let summary = json!({
        "kind": "publish-root",
        "path": path_name(&picked),
        "from": picked.label,
        "fromAddress": format!("{:#x}", picked.address),
    });
    if !want_broadcast(app, &summary)? {
        return Ok(());
    }
    let slot = publish_root(app, &picked).await?;
    if app.non_interactive {
        println!("{}", json!({ "rootSlot": slot, "plan": summary }));
    } else {
        println!("published current root at slot {slot}");
    }
    Ok(())
}

async fn published_slot(app: &App, provider: &impl Provider, epoch: u64) -> Result<u64> {
    use alloy::rpc::types::Filter;
    use kohaku_minimal_shield::abis::ShieldedPool::RootPublished;
    let current = ShieldedPool::new(app.net.pool, provider)
        .currentRoot()
        .call()
        .await?;
    let filter = Filter::new()
        .address(app.net.pool)
        .event_signature(RootPublished::SIGNATURE_HASH)
        .from_block(app.net.deployed_block);
    let logs = provider.get_logs(&filter).await?;
    let client = chain::frame_client(&app.rpc);
    let latest = client.slot_number().await?;
    let mut best: Option<(u64, u64)> = None;
    for log in logs {
        let Ok(ev) = RootPublished::decode_log(&log.inner) else {
            continue;
        };
        if ev.data.epoch != epoch || ev.data.root != current {
            continue;
        }
        let Some(hash) = log.block_hash else {
            continue;
        };
        let Some(number) = log.block_number else {
            continue;
        };
        let slot = client.slot_number_of(hash).await?;
        if recent_root_window_error(slot, latest).is_some() {
            continue;
        }
        if best.is_none_or(|(seen, _)| number >= seen) {
            best = Some((number, slot));
        }
    }
    best.map(|(_, slot)| slot).context(
        "the current pool root is not in the recent-root window. Run publish-root from an account that can pay gas, then unshield",
    )
}

async fn publish_root(app: &App, from: &Picked) -> Result<u64> {
    let from = refresh_balance(app, from).await?;
    let provider = app.provider().await?;
    let epoch = ShieldedPool::new(app.net.pool, &provider)
        .currentEpoch()
        .call()
        .await?;
    let client = chain::frame_client(&app.rpc);
    let (tip, max_fee) = client.fees().await?;
    let chain = client.chain_id().await?;
    publish_for(app, &from, epoch, chain, tip, max_fee).await
}

async fn publish_for(
    app: &App,
    from: &Picked,
    epoch: u64,
    chain: u64,
    tip: U256,
    max_fee: U256,
) -> Result<u64> {
    let client = chain::frame_client(&app.rpc);
    let nonce = client.tx_count(from.address).await?;
    let tx = make_publish_tx(app, from, epoch, chain, tip, max_fee, nonce).await?;
    ensure_can_pay(from.balance, tx.max_cost(), U256::ZERO)?;
    if !app.non_interactive {
        println!("publishing epoch {epoch} root");
    }
    let receipt = send_and_wait(&client, &tx).await?;
    let block_hash = receipt
        .get("blockHash")
        .and_then(Value::as_str)
        .context("publish receipt missing blockHash")?;
    let block_hash: B256 = block_hash.parse()?;
    let block_number = receipt
        .get("blockNumber")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
        .context("publish block")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let head = client.block_number().await?;
        if head >= block_number.saturating_add(2) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for publish confirmations");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let slot = client.slot_number_of(block_hash).await?;
    if let Some(err) = recent_root_window_error(slot, client.slot_number().await?) {
        bail!("{err}");
    }
    Ok(slot)
}

async fn provider_for(app: &App) -> Result<PoolProvider> {
    let url_provider = app.provider().await?;
    let path = chain::indexer_path(&app.root, &app.name, &app.net.name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = Store::new(FileStore::open(path)?);
    let pool = chain::pool_of(&app.net);
    let rpc =
        RpcSyncer::new(url_provider)
            .with_progress(block_sync_progress("syncing shielded pool", None));
    let indexer = Indexer::new(
        pool,
        store,
        sync_cache::syncer_for(
            rpc.clone(),
            sync_cache::cache_path(&app.root, &app.net.name),
            &pool,
        ),
        Verifier::new(rpc),
    );
    Ok(PoolProvider::new(indexer))
}

fn estimate_public_rpc_steps(app: &App) -> u64 {
    estimate_public_rpc_steps_for(
        app.net.tokens.len() as u64,
        app.secrets.public_indexes.len() as u64,
        &app.secrets.smart_indexes,
        app.net.acct_factory.is_zero(),
    )
}

/// RPC ticks for public-address sync, aligned with [`accounts::load_smart`].
///
/// Smart scan probes `0..=max(seen)` then one empty lookahead (`max+1`), not the
/// `+8` safety cap. Zero factory means no smart RPCs.
fn estimate_public_rpc_steps_for(
    tokens: u64,
    eoas: u64,
    smart_indexes: &[u32],
    factory_zero: bool,
) -> u64 {
    let eoa_steps = eoas * (1 + tokens);
    if factory_zero {
        return eoa_steps;
    }
    let smart_hi = smart_indexes.iter().copied().max().unwrap_or(0);
    // Slots 0..=hi plus one empty lookahead (matches load_smart early break).
    let smart_slots = u64::from(smart_hi) + 2;
    let kept = smart_indexes.len() as u64;
    eoa_steps + smart_slots * 2 + kept * (1 + tokens)
}

fn block_sync_progress(
    label: &'static str,
    start_block: Option<u64>,
) -> impl Fn(u64, u64) + Send + Sync {
    crate::ui::block_sync_progress(label, start_block)
}

async fn seed_event_cache(root: &std::path::Path, net: &Network, without_tor: bool) {
    let Ok(raw) = std::env::var("EVENT_CACHE_ENDPOINT") else {
        return;
    };
    let path = sync_cache::cache_path(root, &net.name);
    if path.exists() {
        match SyncCache::open(&path, net.chain_id, net.pool, net.deployed_block) {
            Ok(cache) if !cache.is_empty() => return,
            Ok(_) => {}
            Err(err) => {
                eprintln!("event cache not replaced: {err}");
                return;
            }
        }
    }
    let Ok(url) = raw.parse::<reqwest::Url>() else {
        eprintln!("EVENT_CACHE_ENDPOINT is not a url");
        return;
    };
    eprintln!("downloading event cache");
    let started = std::time::Instant::now();
    let bytes = if chain::without_tor(without_tor) {
        match reqwest::get(url).await {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) => Ok(bytes.to_vec()),
                Err(err) => Err(anyhow::anyhow!(err)),
            },
            Err(err) => Err(anyhow::anyhow!(err)),
        }
    } else {
        match chain::tor_session().await {
            Ok(tor) => tor.get(&url).await,
            Err(err) => Err(err),
        }
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("event cache download failed: {err}");
            return;
        }
    };
    match sync_cache::install_download(&path, net.chain_id, net.pool, net.deployed_block, &bytes) {
        Ok(()) => eprintln!(
            "event cache saved in {:.1}s",
            started.elapsed().as_secs_f64()
        ),
        Err(err) => eprintln!("event cache download rejected: {err}"),
    }
}

async fn sync_notes(app: &mut App, provider: &impl Provider) -> Result<()> {
    seed_event_cache(&app.root, &app.net, app.without_tor).await;
    let msp = provider_for(app).await?;
    msp.indexer.sync().await?;
    let epoch = ShieldedPool::new(app.net.pool, provider)
        .currentEpoch()
        .call()
        .await
        .unwrap_or(0);
    let spent = spent_nullifiers(app, provider).await?;
    if spent.is_empty() {
        return Ok(());
    }
    let mut keep = Vec::new();
    for saved in app.secrets.notes.drain(..) {
        if saved.pending {
            keep.push(saved);
            continue;
        }
        let proof = msp.indexer.tree().leaf_proof(saved.note.commitment()).await;
        let Some(proof) = proof.ok() else {
            keep.push(saved);
            continue;
        };
        let index = index_from_path(&proof.path);
        let mut burned = false;
        for ep in 0..=epoch {
            let nf = saved.note.nullifier(saved.note.domain(ep), ru64(index));
            if spent.contains(&nf) {
                burned = true;
                break;
            }
        }
        if !burned {
            keep.push(saved);
        }
    }
    app.secrets.notes = keep;
    wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
    Ok(())
}

pub async fn hydrate_local_cache(
    root: &std::path::Path,
    net: &Network,
    rpc: reqwest::Url,
    non_interactive: bool,
    without_tor: bool,
) -> Result<()> {
    if net.pool.is_zero() {
        bail!("this network has no pool");
    }
    seed_event_cache(root, net, without_tor).await;
    let pool = chain::pool_of(net);
    let path = sync_cache::cache_path(root, &net.name);
    let provider = chain::http_provider(rpc, without_tor).await?;
    let head = provider.get_block_number().await?;
    let mut cache = SyncCache::open(&path, pool.chain_id, pool.address, pool.deployed_block)?;
    let from = cache.through().saturating_add(1).max(pool.deployed_block);
    let syncer =
        RpcSyncer::new(provider).with_progress(block_sync_progress("hydrating cache", Some(from)));
    if from <= head && !non_interactive {
        eprintln!("hydrating cache blocks {from}..={head}");
    }
    let extended = if from > head {
        Extend::Stored {
            through: cache.through(),
        }
    } else {
        let fetched = syncer.fetch(&pool, from, head).await?;
        cache.extend(from, head, &fetched)?
    };
    let through = match extended {
        Extend::Stored { through } | Extend::Full { through } => through,
    };
    let full = matches!(extended, Extend::Full { .. });
    if non_interactive {
        println!(
            "{}",
            json!({
                "path": path.display().to_string(),
                "throughBlock": through,
                "bytes": cache.len_bytes(),
                "full": full,
            })
        );
    } else {
        println!("cache {}", path.display());
        println!("through block {through}");
        println!("size {} bytes", cache.len_bytes());
        if full {
            println!("cache is 1GB; not storing events past block {through}");
        }
    }
    Ok(())
}

async fn spent_nullifiers(
    app: &App,
    provider: &impl Provider,
) -> Result<std::collections::HashSet<Ruint>> {
    use alloy::rpc::types::Filter;
    use kohaku_minimal_shield::abis::ShieldedPool::NoteSpent;
    let path = sync_cache::cache_path(&app.root, &app.net.name);
    let mut from = app.net.deployed_block;
    let mut out = std::collections::HashSet::new();
    if path.exists() {
        let mut cache = SyncCache::open(
            &path,
            app.net.chain_id,
            app.net.pool,
            app.net.deployed_block,
        )?;
        let through = cache.through();
        for nf in cache.spent_through(through)? {
            out.insert(nf);
        }
        from = through.saturating_add(1).max(from);
    }
    let head = provider.get_block_number().await?;
    if from > head {
        return Ok(out);
    }
    let filter = Filter::new()
        .address(app.net.pool)
        .event_signature(NoteSpent::SIGNATURE_HASH)
        .from_block(from);
    let logs = provider.get_logs(&filter).await?;
    for log in logs {
        if let Some(topic) = log.topics().get(1) {
            out.insert(Ruint::from_be_bytes(topic.0));
        }
    }
    Ok(out)
}

fn index_from_path(path: &[u8]) -> u64 {
    path.iter().enumerate().fold(
        0u64,
        |acc, (i, bit)| {
            if *bit == 0 { acc } else { acc + (1u64 << i) }
        },
    )
}

async fn pick_from(app: &App, spec: Option<&str>, must_pay: bool) -> Result<Picked> {
    let (eoas, _) = accounts::load_eoas(
        app.rpc.clone(),
        app.without_tor,
        &app.secrets,
        &[],
        || {},
    )
    .await?;
    let (smart, _) = accounts::load_smart(
        app.rpc.clone(),
        app.without_tor,
        &app.net,
        &app.secrets,
        &[],
        || {},
    )
    .await?;
    if let Some(spec) = spec {
        return picked_from_spec(&eoas, &smart, spec);
    }
    if app.non_interactive {
        bail!("--from is required");
    }
    let mut labels = Vec::new();
    let mut picks = Vec::new();
    for e in &eoas {
        labels.push(format!(
            "{}  {:#x}  {}",
            e.index,
            e.signer.address(),
            fmt(e.balance)
        ));
        picks.push(from_eoa(e));
    }
    for s in &smart {
        labels.push(format!(
            "a{}  {:#x}  {}",
            s.index,
            s.account,
            fmt(s.balance)
        ));
        picks.push(from_smart(s));
    }
    if picks.is_empty() {
        bail!("no accounts yet. Run next-fresh-address.");
    }
    let i = Select::new()
        .with_prompt(if must_pay { "From account" } else { "Account" })
        .items(&labels)
        .interact()?;
    Ok(picks.remove(i))
}

fn from_eoa(e: &Eoa) -> Picked {
    Picked {
        label: format!("{}", e.index),
        address: e.signer.address(),
        balance: e.balance,
        eoa: Some(e.signer.clone()),
        smart: None,
    }
}

fn from_smart(s: &Smart) -> Picked {
    Picked {
        label: format!("a{}", s.index),
        address: s.account,
        balance: s.balance,
        eoa: None,
        smart: Some(s.clone()),
    }
}

fn picked_from_spec(eoas: &[Eoa], smart: &[Smart], spec: &str) -> Result<Picked> {
    if let Some(rest) = spec.strip_prefix('a') {
        let j: u32 = rest.parse().context("smart selector")?;
        let s = smart
            .iter()
            .find(|s| s.index == j)
            .context("unknown smart account; it has not been allocated")?;
        return Ok(from_smart(s));
    }
    if let Ok(index) = spec.parse::<u32>() {
        let e = eoas.iter().find(|e| e.index == index);
        if let Some(e) = e {
            return Ok(from_eoa(e));
        }
    }
    let addr: Address = spec.parse().context("from account")?;
    if let Some(e) = eoas.iter().find(|e| e.signer.address() == addr) {
        return Ok(from_eoa(e));
    }
    if let Some(s) = smart.iter().find(|s| s.account == addr) {
        return Ok(from_smart(s));
    }
    bail!("account {spec} is not in this wallet")
}

async fn pick_to(
    app: &mut App,
    to: Option<String>,
    allow_new_eoa: bool,
    deployed_smart_only: bool,
) -> Result<Address> {
    if let Some(spec) = to {
        if let Some(rest) = spec.strip_prefix('a') {
            let j: u32 = rest.parse().context("aN")?;
            let smart = load_one_smart(app, j).await?;
            if deployed_smart_only && !smart.deployed {
                bail!(
                    "a{j} is not deployed. Plain unshield needs a deployed account. Use --tail-calls to create it."
                );
            }
            return Ok(smart.account);
        }
        if let Ok(index) = spec.parse::<u32>() {
            return Ok(
                wallet::signer_at(&app.secrets.mnemonic, &wallet::eoa_path(index))?.address(),
            );
        }
        return Ok(spec.parse().context("address")?);
    }
    if app.non_interactive {
        bail!("--to or --next is required");
    }
    let choice = Select::new()
        .with_prompt("Recipient")
        .items(&["Next fresh public address", "Address or selector"])
        .interact()?;
    if choice == 0 && allow_new_eoa {
        let index = app.secrets.next_public;
        let signer = wallet::signer_at(&app.secrets.mnemonic, &wallet::eoa_path(index))?;
        if !app.secrets.public_indexes.contains(&index) {
            app.secrets.public_indexes.push(index);
        }
        app.secrets.next_public = index + 1;
        wallet::save(&app.root, &app.name, &app.password, &app.secrets)?;
        return Ok(signer.address());
    }
    let entered: String = Input::new()
        .with_prompt("Address, public index, or aN")
        .interact_text()?;
    Box::pin(pick_to(
        app,
        Some(entered),
        allow_new_eoa,
        deployed_smart_only,
    ))
    .await
}

async fn pick_value(
    app: &App,
    amount: Option<&str>,
    max: bool,
    balance: U256,
    reserve: U256,
) -> Result<U256> {
    let cap = balance.checked_sub(reserve).unwrap_or(U256::ZERO);
    if cap.is_zero() {
        bail!(
            "balance {} cannot cover gas {}. Unshield ETH to this account first.",
            fmt(balance),
            fmt(reserve)
        );
    }
    let chosen = if max {
        cap
    } else if let Some(raw) = amount {
        from_r(parse_amount(raw)?)
    } else if app.non_interactive {
        bail!("pass --amount-wei, --amount-formatted, or --amount-max");
    } else {
        let entered: String = Input::new()
            .with_prompt(format!("Amount in ETH (max {})", fmt(cap)))
            .interact_text()?;
        if entered == "max" {
            cap
        } else {
            from_r(parse_amount(&entered)?)
        }
    };
    if chosen.is_zero() || chosen > cap {
        bail!(
            "amount {} leaves less than {} for gas. Unshield ETH here first, or lower the amount.",
            fmt(chosen),
            fmt(reserve)
        );
    }
    Ok(chosen)
}

fn parse_amount(raw: &str) -> Result<Ruint> {
    if let Some(rest) = raw.strip_prefix("wei:") {
        return Ok(rest.parse().context("wei")?);
    }
    let parsed = parse_units(raw, 18).context("amount")?;
    let alloy: U256 = parsed.into();
    Ok(to_r(alloy))
}

fn parse_raw(targets: &str, payloads: &str, values: Option<&str>) -> Result<Vec<OutCall>> {
    let targets: Vec<&str> = targets.split(',').filter(|s| !s.is_empty()).collect();
    let payloads: Vec<&str> = payloads.split(',').filter(|s| !s.is_empty()).collect();
    if targets.len() != payloads.len() {
        bail!("targets and payloads must have the same length");
    }
    let values: Vec<U256> = if let Some(v) = values {
        v.split(',')
            .map(|s| s.parse().context("value"))
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![U256::ZERO; targets.len()]
    };
    if values.len() != targets.len() {
        bail!("values must match targets");
    }
    let mut out = Vec::new();
    for ((target, payload), value) in targets.into_iter().zip(payloads).zip(values) {
        let data = hex::decode(payload.trim_start_matches("0x")).context("payload")?;
        out.push(if data.is_empty() {
            OutCall::simple(target.parse()?, value)
        } else {
            OutCall::contract(target.parse()?, value, Bytes::from(data))
        });
    }
    Ok(out)
}

fn parse_tail(spec: &str) -> Result<Vec<Call>> {
    let mut calls = Vec::new();
    for part in spec.split(',') {
        let mut bits = part.split(':');
        let target: Address = bits.next().context("target")?.parse()?;
        let data = hex::decode(bits.next().context("calldata")?.trim_start_matches("0x"))?;
        let value = match bits.next() {
            Some(v) => v.parse().context("value")?,
            None => U256::ZERO,
        };
        calls.push(Call {
            target,
            value,
            data: Bytes::from(data),
        });
    }
    Ok(calls)
}

async fn build_from(
    client: &FrameTxClient,
    from: &Picked,
    calls: Vec<OutCall>,
    tip: U256,
    max_fee: U256,
) -> Result<kohaku_frametx_kit::FrameTx> {
    let nonce = client.tx_count(from.address).await?;
    let chain = client.chain_id().await?;
    if let Some(signer) = &from.eoa {
        return txbuild::eoa_frames(signer, &calls, nonce, chain, tip, max_fee);
    }
    let smart = from.smart.as_ref().context("account")?;
    if !smart.deployed {
        bail!(
            "a{} is not deployed and has no ETH. Unshield to a{} first, then send this in a second transaction.",
            smart.index,
            smart.index
        );
    }
    let calls: Vec<Call> = calls
        .into_iter()
        .map(|c| Call {
            target: c.target,
            value: c.value,
            data: c.data,
        })
        .collect();
    let exec = calls
        .iter()
        .fold(APPROVE_EXEC, |a, _| a.saturating_add(SETTLE_FRAME_GAS / 4));
    let state = calls
        .iter()
        .fold(APPROVE_STATE, |a, _| a.saturating_add(CALL_STATE_PLACE));
    txbuild::account_frames(
        smart.account,
        &smart.owner,
        &calls,
        nonce,
        chain,
        tip,
        max_fee,
        exec.max(200_000),
        state.max(200_000),
    )
}

const CALL_STATE_PLACE: u64 = 200_000;

fn ensure_can_pay(balance: U256, max_cost: U256, value: U256) -> Result<()> {
    if balance < max_cost + value {
        bail!(
            "this account holds {} which cannot cover {} plus gas {}. Unshield ETH to it first, then retry.",
            fmt(balance),
            fmt(value),
            fmt(max_cost)
        );
    }
    Ok(())
}

fn want_broadcast(app: &App, summary: &Value) -> Result<bool> {
    if app.non_interactive && !app.broadcast_flag {
        println!("{}", json!({ "dryRun": true, "plan": summary }));
        return Ok(false);
    }
    if !app.non_interactive {
        println!("{summary}");
        let ok = Confirm::new()
            .with_prompt("Broadcast?")
            .default(app.broadcast_flag)
            .interact()?;
        return Ok(ok);
    }
    Ok(true)
}

async fn commit_calls(
    app: &App,
    client: &FrameTxClient,
    from: &Picked,
    calls: &[OutCall],
    tip: U256,
    max_fee: U256,
    mut summary: Value,
) -> Result<()> {
    let txs = plan_txs(client, from, calls, tip, max_fee).await?;
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("transactions".into(), json!(txs.len()));
        obj.insert("atomic".into(), json!(calls.len() > 1 && txs.len() == 1));
    }
    if !want_broadcast(app, &summary)? {
        return Ok(());
    }
    let sent = if txs.len() == 1 && calls.len() > 1 && from.eoa.is_some() {
        match send_and_wait(client, &txs[0]).await {
            Ok(receipt) => vec![receipt],
            Err(err) if rejects_atomic_flag(&err.to_string()) => {
                let seq = eoa_sequence(
                    client,
                    from.eoa.as_ref().context("eoa")?,
                    calls,
                    tip,
                    max_fee,
                )
                .await?;
                let mut receipts = Vec::new();
                for tx in &seq {
                    receipts.push(send_and_wait(client, tx).await?);
                }
                receipts
            }
            Err(err) => return Err(err),
        }
    } else {
        let mut receipts = Vec::new();
        for tx in &txs {
            receipts.push(send_and_wait(client, tx).await?);
        }
        receipts
    };
    let hash = sent
        .last()
        .and_then(|r| r.get("transactionHash"))
        .cloned()
        .unwrap_or(Value::Null);
    if app.non_interactive {
        println!("{}", json!({ "hash": hash, "plan": summary }));
    } else {
        println!("mined {hash}");
    }
    Ok(())
}

async fn plan_txs(
    client: &FrameTxClient,
    from: &Picked,
    calls: &[OutCall],
    tip: U256,
    max_fee: U256,
) -> Result<Vec<FrameTx>> {
    let value = calls.iter().fold(U256::ZERO, |acc, call| acc + call.value);
    if from.eoa.is_some() && calls.len() > 1 {
        let batch = build_from(client, from, calls.to_vec(), tip, max_fee).await?;
        let split = match client.simulate(&batch.raw()).await {
            Ok(Some(sim)) => atomic_rejected(&sim),
            _ => false,
        };
        if split {
            let seq = eoa_sequence(
                client,
                from.eoa.as_ref().context("eoa")?,
                calls,
                tip,
                max_fee,
            )
            .await?;
            let cost = seq.iter().fold(U256::ZERO, |acc, tx| acc + tx.max_cost());
            ensure_can_pay(from.balance, cost, value)?;
            return Ok(seq);
        }
        ensure_can_pay(from.balance, batch.max_cost(), value)?;
        return Ok(vec![batch]);
    }
    let tx = build_from(client, from, calls.to_vec(), tip, max_fee).await?;
    ensure_can_pay(from.balance, tx.max_cost(), value)?;
    Ok(vec![tx])
}

async fn call_cost(
    client: &FrameTxClient,
    from: &Picked,
    calls: &[OutCall],
    tip: U256,
    max_fee: U256,
) -> Result<U256> {
    let tx = build_from(client, from, calls.to_vec(), tip, max_fee).await?;
    Ok(tx.max_cost())
}

async fn eoa_sequence(
    client: &FrameTxClient,
    signer: &PrivateKeySigner,
    calls: &[OutCall],
    tip: U256,
    max_fee: U256,
) -> Result<Vec<FrameTx>> {
    let mut nonce = client.tx_count(signer.address()).await?;
    let chain = client.chain_id().await?;
    let mut out = Vec::with_capacity(calls.len());
    for call in calls {
        out.push(txbuild::eoa_frames(
            signer,
            std::slice::from_ref(call),
            nonce,
            chain,
            tip,
            max_fee,
        )?);
        nonce += 1;
    }
    Ok(out)
}

async fn shield_cost(
    app: &App,
    from: &Picked,
    epoch: u64,
    chain: u64,
    tip: U256,
    max_fee: U256,
) -> Result<U256> {
    let mut rng = rand::rng();
    let note = Note::random(ru64(1), chain, app.net.pool, &mut rng);
    Ok(shield_tx(app, from, &note, epoch, chain, tip, max_fee)
        .await?
        .max_cost())
}

async fn shield_tx(
    app: &App,
    from: &Picked,
    note: &Note,
    epoch: u64,
    chain: u64,
    tip: U256,
    max_fee: U256,
) -> Result<FrameTx> {
    let client = chain::frame_client(&app.rpc);
    let nonce = client.tx_count(from.address).await?;
    match (&from.eoa, &from.smart) {
        (Some(signer), None) => {
            let msp = provider_for(app).await?;
            let mut tx = msp.shield(note, signer.address(), nonce, chain, tip, max_fee);
            txbuild::append_pool_publish(&mut tx, app.net.pool, epoch);
            tx.sign_secp256k1(0, signer)?;
            Ok(tx)
        }
        (None, Some(smart)) => {
            if !smart.deployed {
                bail!(
                    "a{} is not deployed. Unshield ETH to it before shielding from it.",
                    smart.index
                );
            }
            txbuild::account_frames(
                smart.account,
                &smart.owner,
                &[
                    Call {
                        target: app.net.pool,
                        value: from_r(note.value),
                        data: txbuild::shield_calldata(note.inner().to_be_bytes::<32>()),
                    },
                    Call {
                        target: app.net.pool,
                        value: U256::ZERO,
                        data: txbuild::publish_calldata(epoch),
                    },
                ],
                nonce,
                chain,
                tip,
                max_fee,
                SETTLE_FRAME_GAS.saturating_mul(2),
                SETTLE_FRAME_STATE_GAS.saturating_mul(2),
            )
        }
        _ => bail!("pick one account"),
    }
}

async fn make_publish_tx(
    app: &App,
    from: &Picked,
    epoch: u64,
    chain: u64,
    tip: U256,
    max_fee: U256,
    nonce: u64,
) -> Result<FrameTx> {
    match &from.eoa {
        Some(signer) => {
            let msp = provider_for(app).await?;
            let mut tx = msp.publish_epoch(signer.address(), nonce, chain, tip, max_fee, epoch);
            tx.sign_secp256k1(0, signer)?;
            Ok(tx)
        }
        None => {
            let smart = from.smart.as_ref().context("publisher")?;
            txbuild::account_frames(
                smart.account,
                &smart.owner,
                &[Call {
                    target: app.net.pool,
                    value: U256::ZERO,
                    data: txbuild::publish_calldata(epoch),
                }],
                nonce,
                chain,
                tip,
                max_fee,
                SETTLE_FRAME_GAS,
                SETTLE_FRAME_STATE_GAS,
            )
        }
    }
}

async fn refresh_balance(app: &App, from: &Picked) -> Result<Picked> {
    let address = from.address;
    let balance = chain::with_isolated_provider(app.rpc.clone(), app.without_tor, |provider| async move {
        Ok(provider.get_balance(address).await?)
    })
    .await?;
    let mut next = from.clone();
    next.balance = balance;
    Ok(next)
}

async fn prompt_tail_account(app: &App) -> Result<Smart> {
    let choice = Select::new()
        .with_prompt("Smart account for the tail")
        .items(&["Next free aN", "Existing aN"])
        .interact()?;
    if choice == 0 {
        return accounts::next_free_smart(
            app.rpc.clone(),
            app.without_tor,
            &app.net,
            &app.secrets,
        )
        .await;
    }
    let entered: String = Input::new().with_prompt("Selector (aN)").interact_text()?;
    let rest = entered
        .strip_prefix('a')
        .context("use aN, for example a0")?;
    let j: u32 = rest.parse().context("smart selector")?;
    load_one_smart(app, j).await
}

fn path_name(picked: &Picked) -> &'static str {
    if picked.eoa.is_some() {
        "eoa"
    } else {
        "account"
    }
}

fn atomic_rejected(sim: &SimulateResult) -> bool {
    if sim.valid == Some(true) {
        return false;
    }
    rejects_atomic_flag(&serde_json::to_string(sim).unwrap_or_default())
}

fn rejects_atomic_flag(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("atomic") || text.contains("flag")
}

async fn send_and_wait(client: &FrameTxClient, tx: &FrameTx) -> Result<Value> {
    client.gate_spend(tx).await?;
    let hash = client.send_raw(&tx.raw()).await?;
    println!("sent {hash:#x}");
    let receipt = client.wait_receipt(hash, 360).await?;
    let ok = receipt
        .get("status")
        .and_then(|v| v.as_str())
        .is_none_or(|s| s == "0x1" || s == "1")
        || receipt
            .get("frameReceipts")
            .and_then(Value::as_array)
            .is_some_and(|f| !f.is_empty());
    if !ok {
        bail!("transaction reverted: {receipt}");
    }
    Ok(receipt)
}

async fn resolve_key(app: &App, account: &str) -> Result<PrivateKeySigner> {
    if let Some(rest) = account.strip_prefix('a') {
        let j: u32 = rest.parse()?;
        return accounts::smart_owner(&app.secrets, j);
    }
    let index: u32 = account.parse().context("account index")?;
    wallet::signer_at(&app.secrets.mnemonic, &wallet::eoa_path(index))
}

fn max_withdrawable(notes: &[Note], fee: Ruint) -> Result<Ruint> {
    let total = notes.iter().fold(Ruint::ZERO, |acc, note| acc + note.value);
    let mut amount = total.saturating_sub(fee);
    let mut rng = rand::rng();
    while !amount.is_zero() {
        match plan_unshield(notes, amount, fee, &mut rng) {
            Ok(_) => return Ok(amount),
            Err(SelectError::Insufficient { .. }) => amount = amount.saturating_sub(fee),
            Err(SelectError::ZeroAmount) => break,
        }
    }
    bail!("private balance cannot cover the fees")
}

fn ru64(n: u64) -> Ruint {
    Ruint::try_from(n).expect("u64 fits in U256")
}

fn b256(v: Ruint) -> B256 {
    B256::from_slice(&v.to_be_bytes::<32>())
}

fn to_r(v: U256) -> Ruint {
    Ruint::from_be_bytes::<32>(v.to_be_bytes::<32>())
}

fn from_r(v: Ruint) -> U256 {
    U256::from_be_bytes::<32>(v.to_be_bytes::<32>())
}

fn fmt(v: U256) -> String {
    alloy::primitives::utils::format_ether(v)
}

fn fmt_units(v: U256, decimals: u8) -> String {
    alloy::primitives::utils::format_units(v, decimals).unwrap_or_else(|_| v.to_string())
}

fn token_json(held: &[Held]) -> Vec<Value> {
    held.iter()
        .map(|h| {
            json!({
                "symbol": h.symbol,
                "amount": h.amount.to_string(),
            })
        })
        .collect()
}

fn fmt_r(v: Ruint) -> String {
    fmt(from_r(v))
}

#[cfg(test)]
mod tests {
    use super::{
        atomic_rejected, estimate_public_rpc_steps_for, max_withdrawable, rejects_atomic_flag, ru64,
    };
    use alloy::primitives::Address;
    use kohaku_frametx_kit::SimulateResult;
    use kohaku_minimal_shield::{Note, plan_unshield};

    fn sim(valid: Option<bool>, violation: Option<&str>) -> SimulateResult {
        SimulateResult {
            valid,
            prefix_shape: None,
            payer: None,
            execution_status: None,
            execution_error: None,
            violation: violation.map(|v| serde_json::json!(v)),
            gas_used: None,
            frames: None,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn valid_batch_is_kept() {
        assert!(!atomic_rejected(&sim(Some(true), Some("atomic flag"))));
    }

    #[test]
    fn rejected_atomic_flag_splits() {
        assert!(atomic_rejected(&sim(
            Some(false),
            Some("unknown atomic flag")
        )));
        assert!(rejects_atomic_flag("invalid flags"));
        assert!(!rejects_atomic_flag("insufficient funds"));
    }

    #[test]
    fn max_withdrawable_pays_every_merge_fee() {
        let mut rng = rand::rng();
        let notes = vec![
            Note::random(ru64(10), 8141, Address::ZERO, &mut rng),
            Note::random(ru64(10), 8141, Address::ZERO, &mut rng),
            Note::random(ru64(10), 8141, Address::ZERO, &mut rng),
        ];
        let fee = ru64(1);
        let amount = max_withdrawable(&notes, fee).unwrap();
        let plan = plan_unshield(&notes, amount, fee, &mut rng).unwrap();
        assert_eq!(plan.merges.len(), 1);
        assert_eq!(amount, ru64(28));
    }

    #[test]
    fn public_rpc_estimate_skips_smart_when_factory_zero() {
        // 2 EOAs × (1 balance + 3 tokens) = 8; smart ignored.
        assert_eq!(
            estimate_public_rpc_steps_for(3, 2, &[0, 5], true),
            8
        );
    }

    #[test]
    fn public_rpc_estimate_empty_smart_probes_two_slots() {
        // hi=0 empty → 2 slots × 2 (predict+code); no kept balances/tokens.
        // 1 EOA × (1 + 0 tokens) + 4 = 5.
        assert_eq!(estimate_public_rpc_steps_for(0, 1, &[], false), 5);
    }

    #[test]
    fn public_rpc_estimate_hi_five_uses_lookahead_not_plus_eight() {
        // hi=5 → 7 slots × 2 = 14; kept=1 → balance + 2 tokens = 3.
        // eoas=0 → 14 + 3 = 17.
        assert_eq!(estimate_public_rpc_steps_for(2, 0, &[5], false), 17);
    }
}
