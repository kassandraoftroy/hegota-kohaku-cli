//! Unencrypted pool-event cache shared by every wallet in the data directory.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use alloy::{primitives::Address, providers::Provider};
use anyhow::{Context, Result, bail};
use kohaku_minimal_shield::{
    Pool,
    indexer::{
        rpc::{LoggedEvent, RpcSyncer},
        syncer::{SyncEvent, Syncer, SyncerBackend, SyncerError},
    },
};
use ruint::aliases::U256;

const MAGIC: &[u8; 4] = b"KHPC";
const VERSION: u8 = 1;
const HEADER_LEN: u64 = 64;
pub const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

pub fn cache_path(root: &Path, network: &str) -> PathBuf {
    root.join(format!("pool-sync-{network}.bin"))
}

/// Replace `path` with `bytes` after the existing header checks accept them.
///
/// # Errors
/// Returns when the download is not a cache for this chain and pool.
pub fn install_download(
    path: &Path,
    chain_id: u64,
    pool: Address,
    deployed_block: u64,
    bytes: &[u8],
) -> Result<()> {
    let tmp = path.with_extension("bin.part");
    fs::write(&tmp, bytes).with_context(|| format!("{}", tmp.display()))?;
    match SyncCache::open(&tmp, chain_id, pool, deployed_block) {
        Ok(cache) => drop(cache),
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
    }
    fs::rename(&tmp, path).with_context(|| format!("{}", path.display()))?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Header {
    chain_id: u64,
    pool: Address,
    /// Last block fully scanned, inclusive. One below `deployed_block` when empty.
    through: u64,
    records_len: u64,
}

pub struct SyncCache {
    file: File,
    header: Header,
    deployed_block: u64,
    max_bytes: u64,
}

pub enum Extend {
    Stored { through: u64 },
    Full { through: u64 },
}

impl SyncCache {
    pub fn open(path: &Path, chain_id: u64, pool: Address, deployed_block: u64) -> Result<Self> {
        Self::open_limited(path, chain_id, pool, deployed_block, MAX_CACHE_BYTES)
    }

    fn open_limited(
        path: &Path,
        chain_id: u64,
        pool: Address,
        deployed_block: u64,
        max_bytes: u64,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let exists = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("{}", path.display()))?;
        let header = if !exists || file.metadata()?.len() == 0 {
            let header = Header {
                chain_id,
                pool,
                through: deployed_block.saturating_sub(1),
                records_len: 0,
            };
            write_header(&mut file, &header)?;
            header
        } else {
            let header = read_header(&mut file)?;
            if header.chain_id != chain_id || header.pool != pool {
                bail!(
                    "sync cache {} is for chain {} pool {:#x}. Delete it to rescan this network.",
                    path.display(),
                    header.chain_id,
                    header.pool
                );
            }
            let end = HEADER_LEN + header.records_len;
            if file.metadata()?.len() > end {
                file.set_len(end)?;
            }
            header
        };
        Ok(Self {
            file,
            header,
            deployed_block,
            max_bytes,
        })
    }

    /// Next block that may be appended. Anything else would leave a hole or rewrite history.
    pub fn next_block(&self) -> u64 {
        self.header
            .through
            .saturating_add(1)
            .max(self.deployed_block)
    }

    pub fn through(&self) -> u64 {
        self.header.through
    }

    /// No block at or after the pool's deploy block is stored yet.
    pub fn is_empty(&self) -> bool {
        self.header.through < self.deployed_block
    }

    pub fn len_bytes(&self) -> u64 {
        HEADER_LEN + self.header.records_len
    }

    pub fn events_through(&mut self, from: u64, to: u64) -> Result<Vec<SyncEvent>> {
        let mut out = Vec::new();
        for logged in self.read_records()? {
            if logged.block >= from && logged.block <= to {
                out.push(logged.event);
            }
        }
        Ok(out)
    }

    pub fn spent_through(&mut self, to: u64) -> Result<Vec<U256>> {
        let mut out = Vec::new();
        for logged in self.read_records()? {
            if logged.block <= to {
                if let SyncEvent::NoteSpent { nf } = logged.event {
                    out.push(nf);
                }
            }
        }
        Ok(out)
    }

    /// Append a scan of `scanned_from ..= scanned_to` only when `scanned_from` is [Self::next_block].
    /// A range that starts later is ignored, so the file never gains a gap.
    /// Stops without writing once the file would pass `max_bytes`.
    pub fn extend(
        &mut self,
        scanned_from: u64,
        scanned_to: u64,
        events: &[LoggedEvent],
    ) -> Result<Extend> {
        if scanned_from != self.next_block() || scanned_to < scanned_from {
            return Ok(Extend::Stored {
                through: self.header.through,
            });
        }
        if scanned_to <= self.header.through {
            return Ok(Extend::Stored {
                through: self.header.through,
            });
        }
        let mut buf = Vec::new();
        let mut covered = self.header.through;
        let mut index = 0;
        let mut stopped = false;
        while index < events.len() {
            if events[index].block <= self.header.through {
                index += 1;
                continue;
            }
            let block = events[index].block;
            let start = index;
            while index < events.len() && events[index].block == block {
                index += 1;
            }
            let encoded: Vec<u8> = events[start..index].iter().flat_map(encode).collect();
            if HEADER_LEN + self.header.records_len + buf.len() as u64 + encoded.len() as u64
                > self.max_bytes
            {
                stopped = true;
                break;
            }
            buf.extend(encoded);
            covered = block;
        }
        self.write_records(&buf)?;
        self.header.through = if stopped { covered } else { scanned_to };
        write_header(&mut self.file, &self.header)?;
        let through = self.header.through;
        if stopped || self.len_bytes() >= self.max_bytes {
            Ok(Extend::Full { through })
        } else {
            Ok(Extend::Stored { through })
        }
    }

    fn write_records(&mut self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.file
            .seek(SeekFrom::Start(HEADER_LEN + self.header.records_len))?;
        self.file.write_all(buf)?;
        self.file.flush()?;
        self.header.records_len += buf.len() as u64;
        Ok(())
    }

    fn read_records(&mut self) -> Result<Vec<LoggedEvent>> {
        self.file.seek(SeekFrom::Start(HEADER_LEN))?;
        let mut buf = vec![0u8; self.header.records_len as usize];
        self.file.read_exact(&mut buf)?;
        decode_records(&buf)
    }
}

pub struct CachingSyncer<P: Provider> {
    inner: RpcSyncer<P>,
    path: PathBuf,
    chain_id: u64,
    pool: Address,
    deployed_block: u64,
}

impl<P: Provider + Clone> CachingSyncer<P> {
    pub fn new(
        inner: RpcSyncer<P>,
        path: PathBuf,
        chain_id: u64,
        pool: Address,
        deployed_block: u64,
    ) -> Self {
        Self {
            inner,
            path,
            chain_id,
            pool,
            deployed_block,
        }
    }
}

fn cache_err(err: anyhow::Error) -> SyncerError {
    SyncerError::other(std::io::Error::other(err.to_string()))
}

#[async_trait::async_trait]
impl<P: Provider + Clone> SyncerBackend for CachingSyncer<P> {
    async fn latest_block(&self, pool: &Pool) -> Result<u64, SyncerError> {
        self.inner.latest_block(pool).await
    }

    async fn sync(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<SyncEvent>, SyncerError> {
        let mut cache = SyncCache::open(&self.path, self.chain_id, self.pool, self.deployed_block)
            .map_err(cache_err)?;
        let through = cache.through();
        let mut events = Vec::new();
        if through >= from_block {
            events.extend(
                cache
                    .events_through(from_block, through.min(to_block))
                    .map_err(cache_err)?,
            );
        }
        let rpc_from = from_block.max(through.saturating_add(1));
        if rpc_from <= to_block && through < to_block {
            let fetched = self.inner.fetch(pool, rpc_from, to_block).await?;
            if rpc_from == cache.next_block() {
                cache
                    .extend(rpc_from, to_block, &fetched)
                    .map_err(cache_err)?;
            }
            events.extend(fetched.into_iter().map(|logged| logged.event));
        }
        Ok(events)
    }
}

pub fn syncer_for<P: Provider + Clone + 'static>(
    rpc: RpcSyncer<P>,
    path: PathBuf,
    pool: &Pool,
) -> Syncer {
    Syncer::new(CachingSyncer::new(
        rpc,
        path,
        pool.chain_id,
        pool.address,
        pool.deployed_block,
    ))
}

fn write_header(file: &mut File, header: &Header) -> Result<()> {
    let mut buf = [0u8; HEADER_LEN as usize];
    buf[..4].copy_from_slice(MAGIC);
    buf[4] = VERSION;
    buf[5..13].copy_from_slice(&header.chain_id.to_le_bytes());
    buf[13..33].copy_from_slice(header.pool.as_slice());
    buf[33..41].copy_from_slice(&header.through.to_le_bytes());
    buf[41..49].copy_from_slice(&header.records_len.to_le_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buf)?;
    file.flush()?;
    Ok(())
}

fn read_header(file: &mut File) -> Result<Header> {
    let mut buf = [0u8; HEADER_LEN as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;
    if &buf[..4] != MAGIC {
        bail!("sync cache has a bad header");
    }
    if buf[4] != VERSION {
        bail!("sync cache version {} is not supported", buf[4]);
    }
    let chain_id = u64::from_le_bytes(buf[5..13].try_into().unwrap());
    let pool = Address::from_slice(&buf[13..33]);
    let through = u64::from_le_bytes(buf[33..41].try_into().unwrap());
    let records_len = u64::from_le_bytes(buf[41..49].try_into().unwrap());
    Ok(Header {
        chain_id,
        pool,
        through,
        records_len,
    })
}

fn encode(event: &LoggedEvent) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&event.block.to_le_bytes());
    match &event.event {
        SyncEvent::LeafAppended {
            cm,
            epoch,
            index,
            new_root,
        } => {
            out.push(1);
            out.extend_from_slice(&cm.to_be_bytes::<32>());
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&new_root.to_be_bytes::<32>());
        }
        SyncEvent::EpochRolled { closed, new_epoch } => {
            out.push(2);
            out.extend_from_slice(&closed.to_le_bytes());
            out.extend_from_slice(&new_epoch.to_le_bytes());
        }
        SyncEvent::NoteSpent { nf } => {
            out.push(3);
            out.extend_from_slice(&nf.to_be_bytes::<32>());
        }
        SyncEvent::RootPublished { epoch } => {
            out.push(4);
            out.extend_from_slice(&epoch.to_le_bytes());
        }
    }
    out
}

fn decode_records(buf: &[u8]) -> Result<Vec<LoggedEvent>> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < buf.len() {
        if buf.len() - i < 9 {
            bail!("truncated sync cache");
        }
        let block = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let kind = buf[i];
        i += 1;
        let event = match kind {
            1 => {
                let cm = take_u256(buf, &mut i)?;
                let epoch = take_u64(buf, &mut i)?;
                let index = take_u32(buf, &mut i)?;
                let new_root = take_u256(buf, &mut i)?;
                SyncEvent::LeafAppended {
                    cm,
                    epoch,
                    index,
                    new_root,
                }
            }
            2 => SyncEvent::EpochRolled {
                closed: take_u64(buf, &mut i)?,
                new_epoch: take_u64(buf, &mut i)?,
            },
            3 => SyncEvent::NoteSpent {
                nf: take_u256(buf, &mut i)?,
            },
            4 => SyncEvent::RootPublished {
                epoch: take_u64(buf, &mut i)?,
            },
            other => bail!("unknown sync cache record {other}"),
        };
        out.push(LoggedEvent { block, event });
    }
    Ok(out)
}

fn take_u64(buf: &[u8], i: &mut usize) -> Result<u64> {
    if buf.len() - *i < 8 {
        bail!("truncated sync cache");
    }
    let n = u64::from_le_bytes(buf[*i..*i + 8].try_into().unwrap());
    *i += 8;
    Ok(n)
}

fn take_u32(buf: &[u8], i: &mut usize) -> Result<u32> {
    if buf.len() - *i < 4 {
        bail!("truncated sync cache");
    }
    let n = u32::from_le_bytes(buf[*i..*i + 4].try_into().unwrap());
    *i += 4;
    Ok(n)
}

fn take_u256(buf: &[u8], i: &mut usize) -> Result<U256> {
    if buf.len() - *i < 32 {
        bail!("truncated sync cache");
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf[*i..*i + 32]);
    *i += 32;
    Ok(U256::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{Extend, MAX_CACHE_BYTES, SyncCache};
    use alloy::primitives::address;
    use kohaku_minimal_shield::indexer::{rpc::LoggedEvent, syncer::SyncEvent};
    use ruint::aliases::U256;

    #[test]
    fn append_reads_back_and_stops_at_the_size_cap() {
        let dir = std::env::temp_dir().join(format!("kohaku-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pool-sync-devnet.bin");
        let pool = address!("0xcb83980f3cc99e258295814375b0a94fe0ac0e86");
        let mut cache = SyncCache::open_limited(&path, 8141, pool, 100, MAX_CACHE_BYTES).unwrap();
        assert_eq!(cache.through(), 99);
        let leaf = LoggedEvent {
            block: 100,
            event: SyncEvent::LeafAppended {
                cm: U256::from(1u64),
                epoch: 2,
                index: 3,
                new_root: U256::from(4u64),
            },
        };
        let spent = LoggedEvent {
            block: 101,
            event: SyncEvent::NoteSpent {
                nf: U256::from(9u64),
            },
        };
        assert!(matches!(
            cache
                .extend(100, 101, &[leaf.clone(), spent.clone()])
                .unwrap(),
            Extend::Stored { through: 101 }
        ));
        let events = cache.events_through(100, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::LeafAppended { index: 3, .. }
        ));
        assert_eq!(cache.spent_through(101).unwrap(), vec![U256::from(9u64)]);

        let tiny = SyncCache::open_limited(&path, 8141, pool, 100, cache.len_bytes()).unwrap();
        let mut tiny = tiny;
        let extra = LoggedEvent {
            block: 102,
            event: SyncEvent::RootPublished { epoch: 2 },
        };
        assert!(matches!(
            tiny.extend(102, 110, &[extra]).unwrap(),
            Extend::Full { through: 101 }
        ));
        assert_eq!(tiny.through(), 101);
        let jump = LoggedEvent {
            block: 500,
            event: SyncEvent::NoteSpent {
                nf: U256::from(7u64),
            },
        };
        assert!(matches!(
            tiny.extend(500, 500, &[jump]).unwrap(),
            Extend::Stored { through: 101 }
        ));
        assert_eq!(tiny.through(), 101);
        assert!(
            tiny.spent_through(500)
                .unwrap()
                .iter()
                .all(|nf| *nf != U256::from(7u64))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
