# chain-sentry

A small watcher that tells you when a crypto team starts doing something on chain,
and stays silent the rest of the time.

Point it at the addresses you care about, schedule it once a day, and read one line
a day. When something actually happens, that line becomes a block of alerts.

Built for Blockscout-compatible explorers. Windows PowerShell 5.1, no dependencies.

## Why not just watch the addresses

Because teams don't deploy from the address you're watching.

The pattern this was written for looks like this: on 14 August 2026 a team address
made its first ever transaction on a chain's mainnet — a 0.003 ETH transfer to a
brand new wallet. That's all it did. Ten hours later *that* wallet deployed two
contracts, and the day after, the project announced itself.

A watcher looking only at the known addresses sees the gas transfer and reports a
rounding error. The deployment happens one hop away, where nobody is looking.

So `chain-sentry` follows the money: any ordinary address that receives native
currency from an address you watch is added to the watch list, and its contract
deployments get reported.

## What it checks

- **Watched addresses**, across several chains at once, mainnet and testnet
- **Wallets funded by them** — one hop deep, with their contract deployments
- **New contracts matching the project's name**, filtered so impostors don't drown
  the log (see below)
- **Placeholder pages** — when the markers that make a page a placeholder start
  disappearing, something is being prepared
- **Price and market cap** via CoinGecko, so the log records what the market was
  doing on the day a signal fired

## Design rules it follows

**Alert on change, not on state.** An alert that fires because a condition is true
will fire again tomorrow, and every day after, until you stop reading the log.
Everything here is compared against the previous run.

**The first run is silent.** With no stored state, existing history is
indistinguishable from a fresh event, so the first run records what is already
there and watches from that point. It tells you what it recorded.

**Popular names attract impostors.** A chain can hold a hundred copies of a name
before the real project ships. A baseline snapshot plus an optional template supply
filter keeps the mass-produced ones out of the alert block, where they'd bury the
one contract that matters.

**Compare timestamps, not counts.** Explorers page results, so a busy address
reports the same count forever. The newest transaction timestamp doesn't lie.

## Usage

```powershell
.\watch.ps1 -Config config\unipeg.json
```

Add `-Quiet` to suppress console output and only write the log.

Output goes to `outputDir` from the config (or `state\` next to the script):

- `<config>.log` — one line per quiet day, a block when something changed
- `<config>-state.json` — what was seen last run; delete it to re-baseline

### Scheduling it

Windows Task Scheduler, daily:

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\watch.ps1" -Config "C:\path\to\config\unipeg.json" -Quiet'
$trigger = New-ScheduledTaskTrigger -Daily -At 10:05
Register-ScheduledTask -TaskName 'ChainSentry' -Action $action -Trigger $trigger
```

## Configuration

Copy `config/example.json` and edit it. Every section is optional except `chains`.

```json
{
  "name": "Example project",
  "language": "en",
  "outputDir": "C:\\Users\\You\\Desktop\\Example",

  "chains": [
    {
      "name": "Some mainnet",
      "explorer": "https://blockscout.example.com",
      "followFunding": true,
      "addresses": [
        { "address": "0x...", "label": "team deployer" }
      ],
      "nameSearch": {
        "queries": ["example"],
        "ignoreSupply": "1000000000000000000000000000"
      }
    }
  ],

  "websites": [
    { "url": "https://example.com/", "markers": ["COMING SOON", "noindex"] }
  ],

  "price": {
    "platform": "ethereum",
    "contract": "0x...",
    "symbol": "EXMPL",
    "alertChangePercent": 30
  }
}
```

| Field | Meaning |
| --- | --- |
| `language` | `en` or `ru` — picks a file from `lang/`. Add your own. |
| `outputDir` | Where the log and state file go. Defaults to `state\`. |
| `chains[].explorer` | Blockscout base URL, no trailing slash. |
| `chains[].followFunding` | Watch wallets this chain's addresses send funds to. |
| `chains[].nameSearch.queries` | Terms to search the explorer for. |
| `chains[].nameSearch.ignoreSupply` | Total supply shared by template copies, in wei. |
| `websites[].markers` | Regexes that should stay present. Alerts when one is gone. |
| `price.platform` | CoinGecko platform id, e.g. `ethereum`. |
| `price.alertChangePercent` | Absolute 24h move that triggers an alert. Default 30. |

## Adding a language

Copy `lang/en.json`, translate the values, save as `lang/<code>.json`, and set
`"language": "<code>"`. Placeholders in `{braces}` are substituted, so leave them
alone. The script itself stays plain ASCII on purpose: Windows PowerShell 5.1
corrupts non-ASCII source files that lack a byte order mark, and keeping the text
in JSON sidesteps that entirely.

## The second engine: `metrics-watch.py`

`watch.ps1` watches **addresses** — it asks an explorer whether anything moved.
`metrics-watch.py` watches **the numbers a project produces**, by reading event logs
from an RPC node and doing the arithmetic itself. It keeps both design rules above:
alert on a change of state, and stay silent on the first run while it records a baseline.

Four profiles, chosen per config with `"profile"`:

| profile | what it measures | alerts on |
|---|---|---|
| `launchpad` | launches per day, protocol revenue per day, tokens burned, biggest coin the platform shipped | a metric crossing a floor or ceiling you set |
| `tokens` | a named watchlist: price, 24h move, market cap, liquidity | a daily move past `movePercent`, liquidity under `liquidityBelowUsd` |
| `wallet` | what an address actually holds, airdrop spam filtered out by USD value | total value moving past `totalMovePercent`, liquidity draining under a holding |
| `lp` | concentrated liquidity positions: whether the price is still inside the range, how far the nearest edge is, what the position now consists of, fees accrued | leaving the range, coming back into it, and coming within `edgePercent` of an edge |

### The `lp` profile

A concentrated position stops earning the moment the price leaves its range, and nothing
tells you: the position is not a token in the wallet, and on a hook-based DEX it is not
even an NFT — the hook keeps one shared position per range and hands out ERC-6909 shares
for it. So the profile reads the hook directly:

| call | what it gives |
|---|---|
| `rangeKey(id)` | the pool key and the range's two ticks |
| `balanceOf(owner, id)` | the shares this owner holds in that range |
| `rangeState(id)` | total shares and the range's fee-growth counters |
| `userPosition(id, owner)` | what is owed, and this position's own checkpoints |
| `StateView.getSlot0(poolId)` | the pool's current tick |

Fees are not paid out and never appear in the wallet: they accumulate as a growth counter,
and a position owns the growth since its own checkpoint —
`owed + shares * (accFee - checkpoint) / 2**128`. That is the number a points programme
scores, so it is reported even when it is cents.

Distances to the edges are given in **percent of price**, not in ticks, because percent is
what you can compare against how the coin actually moves. A config lists the positions by
`hook`, `rangeId` and `poolId`; see `config/fables-lp.json`.

Several `--config` flags fold into **one** message, so a morning digest is a single
notification rather than one per project:

```
python metrics-watch.py --config config/stonkex.json --config config/watchlist.json \
                        --env-file /path/to/.env
python metrics-watch.py --config config/watchlist.json --alerts-only   # silent unless something crossed
python metrics-watch.py --config config/watchlist.json --dry-run       # measure, never send, never touch state
```

Telegram credentials are read from the environment or from `--env-file`; configs hold
only the variable NAMES, so a config is safe to commit.

## Limitations

- `watch.ps1` reads the first page of transactions per address (50 on Blockscout). An
  address with more than 50 transactions in one day could have older ones missed.
- `watch.ps1` is Blockscout only. Etherscan-family explorers use a different API shape.
- Contract deployments are detected via `created_contract`, so internal
  deployments — a contract deploying another contract — are not reported.
- `metrics-watch.py` prices tokens through DexScreener, which returns a capped number
  of pairs per request. Batches are kept small for that reason; a token in very many
  pools can still under-report total liquidity.
- The `wallet` profile needs an explorer that serves `action=tokenlist`. Public
  Blockscout rate-limits it, so the call retries with backoff rather than failing fast.
- The `lp` profile assumes the second currency of a pair is the dollar quote, which is
  true for the stablecoin-quoted pools it was built against and wrong for a pool of two
  volatile coins. It also assumes shares map one-to-one onto liquidity, which holds for
  the hook it was written for; verify before pointing it at a different one.
- Run it from a scheduler on Windows through `pythonw.exe`, not `python.exe`. A console
  process there was being handed a close signal mid-run and dying with
  `STATUS_CONTROL_C_EXIT` (`0xC000013A`), which looks exactly like a run that never
  happened: the header in the log, nothing after it.

## Licence

MIT
