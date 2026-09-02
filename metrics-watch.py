#!/usr/bin/env python3
"""
chain-sentry metrics engine.

The PowerShell engine (watch.ps1) watches ADDRESSES: it asks an explorer whether
anything moved. This engine watches NUMBERS a protocol produces -- launches per
day, revenue per day, tokens burned, the size of what the protocol ships -- by
reading event logs straight from an RPC node and doing the arithmetic itself.

It keeps the two rules the PowerShell engine established:
  * alert on a CHANGE of state, never on the state itself;
  * the first run is silent -- it records a baseline and says so.

Profiles, chosen per config with "profile":
    launchpad  events a protocol emits: launches per day, revenue, burn, what it shipped
    tokens     a named watchlist: price, 24h move, cap, liquidity
    wallet     what an address actually holds, airdrop spam filtered out by value
    lp         concentrated liquidity positions: is the price still inside the range,
               how close to an edge, what the position is made of, fees accrued

Usage:
    python metrics-watch.py --config config/stonkex.json --config config/watchlist.json
    python metrics-watch.py --config config/stonkex.json --alerts-only  (silent unless something crossed)
    python metrics-watch.py --config config/stonkex.json --dry-run      (measure, never send)

Several --config flags fold into ONE message, so a morning digest is one notification
rather than one per project.

Telegram credentials are never stored in this repo. They are read from the
environment, or from an env file named with --env-file (KEY=value per line).
"""

import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCK_SECONDS = 2  # Base produces a block every 2 seconds, deterministically.
USER_AGENT = "chain-sentry/metrics"


# --------------------------------------------------------------- plumbing

def http_json(url, payload=None, timeout=45, retries=3):
    """GET or POST JSON with retries. Returns parsed JSON or raises."""
    data = None
    headers = {"user-agent": USER_AGENT}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["content-type"] = "application/json"
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except Exception as exc:  # noqa: BLE001 - any transport failure is retryable
            last = exc
            time.sleep(1.5 * (attempt + 1))

    # Python ships its own CA bundle and it goes stale: a certificate the operating
    # system trusts perfectly well can come back as "expired" here. curl uses the
    # Windows store, so it is the fallback rather than switching verification off.
    try:
        return _curl_json(url, data, timeout)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("request failed after %d tries: %s (curl fallback: %s)"
                           % (retries, last, exc))


def _curl_json(url, data, timeout):
    import subprocess
    cmd = ["curl", "-s", "--max-time", str(timeout), "-H", "user-agent: " + USER_AGENT]
    if data is not None:
        cmd += ["-X", "POST", "-H", "content-type: application/json", "--data-binary", "@-"]
    cmd.append(url)
    # Give curl no console of its own. Run from the scheduler this is not cosmetic:
    # a console child there was being handed a close signal and died with
    # STATUS_CONTROL_C_EXIT, so the fallback failed on exactly the runs that needed it.
    flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    proc = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout + 10,
                          creationflags=flags)
    if proc.returncode != 0:
        raise RuntimeError("curl exited %d: %s" % (proc.returncode, proc.stderr[:200]))
    return json.loads(proc.stdout.decode("utf-8", "replace"))


class Rpc:
    """Round-robins over several public nodes so one flaky node cannot stop a run."""

    def __init__(self, urls):
        self.urls = list(urls)

    def call(self, method, params):
        errors = []
        for url in self.urls:
            try:
                # One try per node, not three: falling through to the next node is
                # faster than waiting out a retry backoff on a node that said no.
                out = http_json(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                                retries=1)
                if "result" in out and out["result"] is not None:
                    return out["result"]
                errors.append("%s: %s" % (url, out.get("error")))
            except Exception as exc:  # noqa: BLE001
                errors.append("%s: %s" % (url, exc))
        raise RuntimeError("all nodes failed for %s -- %s" % (method, "; ".join(errors)))

    def logs(self, address, topic, from_block, to_block, step=40000):
        """eth_getLogs over a range, split into chunks a public node will accept."""
        out = []
        start = from_block
        while start <= to_block:
            end = min(start + step - 1, to_block)
            try:
                chunk = self.call("eth_getLogs", [{
                    "address": address,
                    "topics": [topic],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                }])
            except RuntimeError:
                if step <= 5000:
                    raise
                step = max(5000, step // 2)
                continue
            out.extend(chunk)
            start = end + 1
        return out


def load_env_file(path):
    """Read KEY=value lines into os.environ without overwriting what is already set."""
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# --------------------------------------------------------------- decoding

def words(hexdata, count):
    """Split ABI-encoded data (without 0x) into `count` 32-byte words."""
    body = hexdata[2:] if hexdata.startswith("0x") else hexdata
    return [body[i * 64:(i + 1) * 64] for i in range(count)]


def addr_of(word):
    return "0x" + word[-40:].lower()


def uint_of(word):
    return int(word, 16) if word else 0


def pad_addr(address):
    return "0x" + "0" * 24 + address[2:].lower()


def sint_of(word):
    """Signed integer. Ticks are int24 stored in two's complement over 32 bytes."""
    value = int(word, 16) if word else 0
    return value - (1 << 256) if value >= (1 << 255) else value


# --------------------------------------------------------------- prices

def dexscreener_tokens(addresses, batch_size=5):
    """Best pair per token address, keyed by lowercase address.

    The endpoint caps how many PAIRS it returns per call, not how many tokens, so a
    token with many pools crowds its neighbours out of the answer entirely. Small
    batches cost more requests and are the only way to get every token priced.
    """
    best = {}
    addresses = [a for a in addresses if a]
    for i in range(0, len(addresses), batch_size):
        batch = ",".join(addresses[i:i + batch_size])
        try:
            data = http_json("https://api.dexscreener.com/latest/dex/tokens/" + batch, retries=2)
        except Exception:  # noqa: BLE001 - price data is best effort
            continue
        totals = {}
        for pair in (data.get("pairs") or []):
            key = pair["baseToken"]["address"].lower()
            liq = (pair.get("liquidity") or {}).get("usd") or 0
            totals[key] = totals.get(key, 0) + liq
            if key not in best or liq > best[key]["liquidity"]:
                best[key] = {
                    "symbol": pair["baseToken"]["symbol"],
                    "price": float(pair.get("priceUsd") or 0),
                    "liquidity": liq,
                    "marketCap": pair.get("marketCap") or pair.get("fdv") or 0,
                    "volume24": (pair.get("volume") or {}).get("h24") or 0,
                    "change24": (pair.get("priceChange") or {}).get("h24"),
                    # Kept for the picture digest: the project's own logo.
                    "imageUrl": (pair.get("info") or {}).get("imageUrl"),
                }
        for key, total in totals.items():
            if key in best:
                best[key]["liquidityTotal"] = total
    return best


# --------------------------------------------------------------- measuring

def day_key(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")


def measure(cfg, rpc, log, days_back):
    """Collect every metric this run needs. Returns a dict of plain numbers."""
    w = cfg["watch"]
    locker = w["locker"].lower()
    token = w["token"].lower()
    dead = w["deadAddress"].lower()
    quote_native = w["quoteNative"].lower()
    equity_prefix = w["equityPrefix"].lower()

    head = rpc.call("eth_blockNumber", [])
    latest = int(head, 16)
    head_block = rpc.call("eth_getBlockByNumber", [hex(latest), False])
    head_ts = int(head_block["timestamp"], 16)

    def block_at(ts):
        return max(1, latest - int((head_ts - ts) / BLOCK_SECONDS))

    def ts_of(block):
        return head_ts - (latest - block) * BLOCK_SECONDS

    # Whole UTC days back, so the last completed day is always covered end to end.
    today_start = dt.datetime.fromtimestamp(head_ts, dt.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)
    window_start = today_start - dt.timedelta(days=days_back)
    window_start_ts = int(window_start.timestamp())
    from_block = block_at(window_start_ts)
    log("scanning blocks %d..%d (%s -> now)" % (from_block, latest, day_key(window_start_ts)))

    # Every day in the window starts at zero. A day with NO launches is the loudest
    # signal there is, and it has no log entry to be discovered from.
    calendar = {}
    cursor = window_start
    while cursor <= today_start:
        calendar[cursor.strftime("%Y-%m-%d")] = 0
        cursor += dt.timedelta(days=1)

    launches = dict(calendar)
    for entry in rpc.logs(locker, w["topicPositionRegistered"], from_block, latest):
        key = day_key(ts_of(int(entry["blockNumber"], 16)))
        launches[key] = launches.get(key, 0) + 1

    fee_logs = rpc.logs(locker, w["topicFeesCollected"], from_block, latest)

    # Which assets appear on the quote side -- we price those, and only those.
    assets = set()
    child_tokens = set()
    for entry in fee_logs:
        parts = words(entry["data"], 8)
        for token_addr in (addr_of(parts[0]), addr_of(parts[1])):
            if token_addr == quote_native or token_addr.startswith(equity_prefix):
                assets.add(token_addr)
            elif token_addr != token:
                child_tokens.add(token_addr)

    prices = dexscreener_tokens(sorted(assets | {token}))
    native_price = prices.get(quote_native, {}).get("price", 0)

    # Decimals belong to the token, not to the address prefix it shares with others.
    # cbHYPE sits under the same 0xb2 prefix as the tokenized stocks and has 18 of
    # them, not 8: assuming the configured default turned one $100 fee into $999bn
    # and one day's revenue into a trillion dollars. Asked once per asset per run.
    asset_decimals = {}
    for address in sorted(assets):
        fallback = 18 if address == quote_native else w["equityDecimals"]
        try:
            answer = rpc.call("eth_call", [
                {"to": address, "data": w.get("decimalsSelector", "0x313ce567")}, "latest"])
            asset_decimals[address] = int(answer, 16) if answer not in (None, "0x") else fallback
        except Exception:  # noqa: BLE001 - an unreadable token keeps the configured guess
            asset_decimals[address] = fallback
        if asset_decimals[address] != fallback:
            log("%s reports %d decimals, not the %d assumed for its prefix"
                % (address, asset_decimals[address], fallback))

    revenue = dict((day, 0.0) for day in calendar)
    for entry in fee_logs:
        parts = words(entry["data"], 8)
        day = day_key(ts_of(int(entry["blockNumber"], 16)))
        pairs = ((addr_of(parts[0]), uint_of(parts[4])), (addr_of(parts[1]), uint_of(parts[5])))
        for token_addr, raw in pairs:
            if token_addr not in asset_decimals:
                continue
            price = native_price if token_addr == quote_native else \
                prices.get(token_addr, {}).get("price", 0)
            revenue[day] = revenue.get(day, 0.0) + raw / (10.0 ** asset_decimals[token_addr]) * price

    burned_raw = rpc.call("eth_call", [
        {"to": token, "data": w["balanceOfSelector"] + pad_addr(dead)[2:]}, "latest"])
    burned = int(burned_raw, 16) / 1e18

    supply_raw = rpc.call("eth_call", [{"to": token, "data": w["totalSupplySelector"]}, "latest"])
    supply = int(supply_raw, 16) / 1e18

    # Asked on its own, not inside the batch: the batch endpoint caps how many pairs
    # it returns per token, which under-reports liquidity for a token in many pools.
    own = dexscreener_tokens([token], batch_size=1).get(token, prices.get(token, {}))
    return {
        "measuredAt": head_ts,
        "block": latest,
        "launchesByDay": launches,
        "revenueByDay": {k: round(v, 2) for k, v in revenue.items()},
        "burned": burned,
        "burnedPercent": (burned / supply * 100) if supply else 0,
        "childTokens": sorted(child_tokens),
        "price": own.get("price", 0),
        "marketCap": own.get("marketCap", 0),
        "liquidity": own.get("liquidityTotal", own.get("liquidity", 0)),
        "volume24": own.get("volume24", 0),
    }


def measure_wallet(cfg, log, known=None):
    """Profile 'wallet': what an address actually holds, spam filtered out by value.

    A Base wallet accumulates hundreds of airdropped tokens nobody asked for. Counting
    them as holdings makes every number meaningless, so anything under `minUsd` is
    dropped -- and how many were dropped is itself reported, because a sudden jump in
    spam is worth seeing.
    """
    w = cfg["watch"]
    address = w["address"]
    url = "%s?module=account&action=tokenlist&address=%s" % (w["explorer"], address)

    # Blockscout answers a rate limit with HTTP 200 and an empty result, so it looks
    # like success to every transport check. Only the message says otherwise.
    entries, complaint, from_cache = None, "", False
    for attempt in range(5):
        listing = http_json(url, retries=1)
        entries = listing.get("result")
        if isinstance(entries, list):
            break
        complaint = str(listing.get("message") or listing)[:120]
        entries = None
        log("explorer said '%s', waiting" % complaint)
        time.sleep(8 * (attempt + 1))

    if entries is None:
        # Discovery is the ONLY thing the explorer is needed for -- every balance is
        # read from the chain anyway. So a rate limit costs us new tokens, not the
        # whole report: fall back to the token list this wallet was already known to
        # hold and say so, rather than dropping the wallet out of the digest entirely.
        if known:
            log("explorer unavailable (%s); reusing %d known tokens" % (complaint, len(known)))
            from_cache = True
            entries = [{"type": "ERC-20", "symbol": k["symbol"], "decimals": str(k.get("decimals", 18)),
                        "contractAddress": k["address"], "balance": "1"} for k in known]
        else:
            raise RuntimeError("explorer returned no token list (%s)" % complaint)

    # Anything the wallet was known to hold is added to whatever the explorer found.
    # The explorer's index lags behind new tokens, so replacing one with the other
    # loses a fresh position; merging keeps both.
    if known and not from_cache:
        seen = {str(e.get("contractAddress", "")).lower() for e in entries}
        for extra in known:
            if extra["address"].lower() not in seen:
                entries = list(entries) + [{
                    "type": "ERC-20", "symbol": extra["symbol"],
                    "decimals": str(extra.get("decimals", 18)),
                    "contractAddress": extra["address"], "balance": "1",
                }]

    held = []
    for item in entries:
        if item.get("type") != "ERC-20":
            continue
        try:
            decimals = int(item.get("decimals") or 18)
        except (TypeError, ValueError):
            decimals = 18
        raw = int(item.get("balance") or 0)
        if raw <= 0:
            continue
        held.append({
            "symbol": (item.get("symbol") or "?")[:18],
            "address": item["contractAddress"].lower(),
            "decimals": decimals,
            "balance": raw / (10 ** decimals),
        })

    prices = dexscreener_tokens([h["address"] for h in held])
    for holding in held:
        info = prices.get(holding["address"], {})
        holding["price"] = info.get("price", 0)
        holding["liquidity"] = info.get("liquidityTotal", info.get("liquidity", 0))
        holding["change24"] = info.get("change24")
        holding["imageUrl"] = info.get("imageUrl")
        holding["usd"] = holding["balance"] * holding["price"]

    merged = {k["address"].lower() for k in (known or [])}
    if from_cache:
        candidates = held
    else:
        # A token carried over from memory has a placeholder balance, so its USD value
        # means nothing yet -- it goes through to the on-chain check regardless.
        candidates = sorted(
            [h for h in held if h["usd"] >= w["minUsd"] or h["address"] in merged],
            key=lambda h: -h["usd"])

    # The explorer's cached balances go stale -- it reported a vault position that had
    # already been withdrawn in full. Discovery can come from the explorer, but the
    # NUMBER has to come from the chain. Only the ones that passed the value filter are
    # re-read, so this stays a handful of calls rather than one per airdrop.
    real, ghosts = [], []
    rpc = Rpc(w["rpc"])
    for holding in candidates:
        try:
            raw = rpc.call("eth_call", [{
                "to": holding["address"],
                "data": "0x70a08231" + pad_addr(address)[2:],
            }, "latest"])
            decimals = holding.get("decimals", 18)
            onchain = int(raw, 16) / (10 ** decimals)
        except Exception:  # noqa: BLE001 - keep the explorer's number if the node is down
            real.append(holding)
            continue
        if onchain <= 0:
            ghosts.append(holding["symbol"])
            continue
        holding["balance"] = onchain
        holding["usd"] = onchain * holding["price"]
        if holding["usd"] >= w["minUsd"]:
            real.append(holding)
    if ghosts:
        log("explorer listed balances the chain does not have: %s" % ", ".join(ghosts))

    real.sort(key=lambda h: -h["usd"])
    return {
        "measuredAt": int(time.time()),
        "fromCache": from_cache,
        "knownTokens": [{"symbol": h["symbol"], "address": h["address"],
                         "decimals": h.get("decimals", 18)} for h in real],
        "holdings": real,
        "totalUsd": sum(h["usd"] for h in real),
        "tokenCount": len(held),
        "spamCount": len(held) - len(real),
    }


def digest_wallet(now, text, previous_total=None):
    change = (now["totalUsd"] - previous_total) if previous_total else None
    lines = [row(sign_of(change), text["walletTotal"].format(
        total=bold(fmt_usd(now["totalUsd"])), kept=len(now["holdings"]),
        spam=now["spamCount"]))]
    for holding in now["holdings"][:8]:
        change = holding.get("change24")
        lines.append(row(sign_of(change), text["walletLine"].format(
            symbol=esc(holding["symbol"]), usd=fmt_usd(holding["usd"]),
            change=fmt_change(change)), logo=holding.get("imageUrl")))
    return lines


def evaluate_wallet(cfg, now, state, text):
    th = cfg["thresholds"]
    flags = dict(state.get("flags", {}))
    alerts = []
    previous = state.get("totalUsd")

    if previous and previous > 0:
        move = (now["totalUsd"] - previous) / previous * 100
        if abs(move) >= th["totalMovePercent"]:
            alerts.append(mark(text, sign_of(move)) + " " + text["walletMoved"].format(
                move=round(move, 1), was=fmt_usd(previous), now=bold(fmt_usd(now["totalUsd"]))))

    # Liquidity draining under a holding is the early warning a price chart gives too late.
    thin = [h for h in now["holdings"] if 0 < h["liquidity"] < th["liquidityBelowUsd"]]
    for holding in thin:
        key = "thin:" + holding["address"]
        if not flags.get(key):
            alerts.append(mark(text, "alarm") + " " + text["walletThin"].format(
                symbol=esc(holding["symbol"]), liq=fmt_usd(holding["liquidity"]),
                limit=fmt_usd(th["liquidityBelowUsd"]), usd=fmt_usd(holding["usd"])))
        flags[key] = True
    for key in [k for k in flags if k.startswith("thin:")]:
        if key not in ["thin:" + h["address"] for h in thin]:
            flags.pop(key, None)

    return alerts, flags


def measure_tokens(cfg, log):
    """Profile 'tokens': a named watchlist, whatever chain each one lives on."""
    entries = cfg["watch"]["tokens"]
    prices = dexscreener_tokens([e["address"].lower() for e in entries], batch_size=1)
    rows = []
    for entry in entries:
        info = prices.get(entry["address"].lower(), {})
        rows.append({
            "label": entry.get("label") or info.get("symbol") or entry["address"][:10],
            "address": entry["address"].lower(),
            "price": info.get("price", 0),
            "change24": info.get("change24"),
            "liquidity": info.get("liquidityTotal", info.get("liquidity", 0)),
            "marketCap": info.get("marketCap", 0),
            "found": bool(info),
            "imageUrl": info.get("imageUrl"),
        })
    missing = [r["label"] for r in rows if not r["found"]]
    if missing:
        log("no market data for: %s" % ", ".join(missing))
    return {"measuredAt": int(time.time()), "rows": rows}


def digest_tokens(now, text):
    lines = []
    for entry in now["rows"]:
        if not entry["found"]:
            lines.append(row("info", text["tokenMissing"].format(label=esc(entry["label"]))))
            continue
        change = entry.get("change24")
        lines.append(row(sign_of(change), text["tokenLine"].format(
            label=esc(entry["label"]), price=fmt_usd(entry["price"]),
            change=fmt_change(change), cap=fmt_usd(entry["marketCap"]),
            liq=fmt_usd(entry["liquidity"])), logo=entry.get("imageUrl")))
    return lines


def evaluate_tokens(cfg, now, state, text):
    th = cfg["thresholds"]
    flags = dict(state.get("flags", {}))
    alerts = []
    for row in now["rows"]:
        if not row["found"]:
            continue
        change = row.get("change24")
        if isinstance(change, (int, float)) and abs(change) >= th["movePercent"]:
            key = "move:%s:%s" % (row["address"], day_key(now["measuredAt"]))
            if not flags.get(key):
                alerts.append(mark(text, sign_of(change)) + " " + text["tokenMoved"].format(
                    label=esc(row["label"]), change=round(change, 1),
                    price=bold(fmt_usd(row["price"]))))
                flags[key] = True
        thin_key = "thin:" + row["address"]
        is_thin = 0 < row["liquidity"] < th["liquidityBelowUsd"]
        if is_thin and not flags.get(thin_key):
            alerts.append(mark(text, "alarm") + " " + text["tokenThin"].format(
                label=esc(row["label"]), liq=fmt_usd(row["liquidity"]),
                limit=fmt_usd(th["liquidityBelowUsd"])))
        flags[thin_key] = is_thin

    # Day-scoped move flags would pile up forever; keep only today's.
    today = day_key(now["measuredAt"])
    flags = {k: v for k, v in flags.items() if not k.startswith("move:") or k.endswith(today)}
    return alerts, flags


def top_child(state, fresh_children, limit):
    """Largest market cap among coins the launchpad has produced."""
    known = sorted(set(state.get("childTokens", [])) | set(fresh_children))
    if not known:
        return 0, None, known
    prices = dexscreener_tokens(known[:limit])
    best_cap, best_symbol = 0, None
    for info in prices.values():
        cap = info.get("marketCap") or 0
        if cap > best_cap:
            best_cap, best_symbol = cap, info.get("symbol")
    return best_cap, best_symbol, known


# --------------------------------------------------------------- liquidity ranges

Q128 = 1 << 128
SEL_RANGE_KEY = "0x2e32a3b0"      # rangeKey(uint256)
SEL_RANGE_STATE = "0x41b69b2a"    # rangeState(uint256)
SEL_USER_POSITION = "0x4eb5c4fd"  # userPosition(uint256,address)
SEL_BALANCE_OF = "0x00fdd58e"     # balanceOf(address,uint256)
SEL_GET_SLOT0 = "0xc815641c"      # StateView.getSlot0(bytes32)
SEL_DECIMALS = "0x313ce567"
SEL_SYMBOL = "0x95d89b41"


def call_view(rpc, to, data):
    return rpc.call("eth_call", [{"to": to, "data": data}, "latest"])


def fmt_small(value):
    """Money that is expected to be cents. fmt_usd keeps six decimals for coin
    prices, which turns 15 cents of fees into unreadable noise."""
    return "$%.2f" % float(value or 0) if float(value or 0) < 1000 else fmt_usd(value)


def token_meta(rpc, address, cache):
    """(symbol, decimals). The zero address means the chain's native coin."""
    address = address.lower()
    if address in cache:
        return cache[address]
    if int(address, 16) == 0:
        cache[address] = ("ETH", 18)
        return cache[address]
    decimals = uint_of(words(call_view(rpc, address, SEL_DECIMALS), 1)[0])
    raw = call_view(rpc, address, SEL_SYMBOL)
    symbol = address[:8]
    try:
        body = raw[2:]
        length = int(body[64:128], 16)
        symbol = bytes.fromhex(body[128:128 + length * 2]).decode("utf-8")
    except Exception:  # noqa: BLE001
        pass
    cache[address] = (symbol, decimals)
    return cache[address]


def tick_price(tick, dec0, dec1):
    return 1.0001 ** tick * 10 ** (dec0 - dec1)


def measure_lp(cfg, rpc, log):
    """Profile 'lp': concentrated liquidity positions on a Uniswap v4 hook.

    A position here is not an NFT and not a token in the wallet: the hook keeps one
    shared position per price range and hands out ERC-6909 shares for it. So the
    range, the shares and the fees all have to be read from the hook itself.
    """
    watch = cfg["watch"]
    owner = watch["owner"].lower()
    state_view = watch["stateView"]
    cache = {}
    rows = []
    for entry in watch["positions"]:
        hook = entry["hook"].lower()
        range_id = entry["rangeId"].lower().replace("0x", "")
        pool_id = entry["poolId"].lower().replace("0x", "")

        key = words(call_view(rpc, hook, SEL_RANGE_KEY + range_id), 8)
        tick_lower, tick_upper = sint_of(key[5]), sint_of(key[6])
        symbol0, dec0 = token_meta(rpc, addr_of(key[0]), cache)
        symbol1, dec1 = token_meta(rpc, addr_of(key[1]), cache)

        shares = uint_of(words(call_view(
            rpc, hook, SEL_BALANCE_OF + pad_addr(owner)[2:] + range_id), 1)[0])
        tick = sint_of(words(call_view(rpc, state_view, SEL_GET_SLOT0 + pool_id), 2)[1])

        st = words(call_view(rpc, hook, SEL_RANGE_STATE + range_id), 4)
        pos = words(call_view(rpc, hook, SEL_USER_POSITION + range_id + pad_addr(owner)[2:]), 5)
        total_shares = uint_of(st[0])
        # Fees are not paid out: they accumulate as a growth counter on the range, and
        # a position owns the growth since its own checkpoint. This is the number the
        # points programme is scored on, so it is worth reporting even when it is cents.
        fee0 = (uint_of(pos[1]) + shares * (uint_of(st[2]) - uint_of(pos[3])) // Q128) / 10.0 ** dec0
        fee1 = (uint_of(pos[2]) + shares * (uint_of(st[3]) - uint_of(pos[4])) // Q128) / 10.0 ** dec1

        low = tick_price(tick_lower, dec0, dec1)
        high = tick_price(tick_upper, dec0, dec1)
        price = tick_price(tick, dec0, dec1)
        edge = min(max(tick, tick_lower), tick_upper)
        sqrt_now = 1.0001 ** (edge / 2.0)
        sqrt_low = 1.0001 ** (tick_lower / 2.0)
        sqrt_high = 1.0001 ** (tick_upper / 2.0)
        amount0 = shares * (1.0 / sqrt_now - 1.0 / sqrt_high) / 10.0 ** dec0
        amount1 = shares * (sqrt_now - sqrt_low) / 10.0 ** dec1
        value = amount0 * price + amount1
        span = max(tick_upper - tick_lower, 1)

        rows.append({
            "label": entry.get("label") or (symbol0 + "/" + symbol1),
            "symbol0": symbol0,
            "symbol1": symbol1,
            "price": price,
            "low": low,
            "high": high,
            "inside": tick_lower <= tick < tick_upper,
            # How far the price has to move to leave, in percent. Percent, not ticks,
            # because that is the number you can compare against how the coin moves.
            "toLow": abs(1.0001 ** (tick_lower - tick) - 1) * 100,
            "toHigh": abs(1.0001 ** (tick_upper - tick) - 1) * 100,
            "atPercent": min(100.0, max(0.0, 100.0 * (tick - tick_lower) / span)),
            "amount0": amount0,
            "amount1": amount1,
            "valueUsd": value,
            "feesUsd": fee0 * price + fee1,
            "sharePercent": (100.0 * shares / total_shares) if total_shares else 0.0,
            "stockPercent": (100.0 * amount0 * price / value) if value else 0.0,
        })
        rows[-1]["nearest"] = min(rows[-1]["toLow"], rows[-1]["toHigh"])
        rows[-1]["near"] = rows[-1]["inside"] and rows[-1]["nearest"] <= cfg["thresholds"]["edgePercent"]
        log("%s: tick %d in [%d, %d], %s, %s, fees %s" % (
            rows[-1]["label"], tick, tick_lower, tick_upper,
            "inside" if rows[-1]["inside"] else "OUT OF RANGE",
            fmt_usd(value), fmt_small(rows[-1]["feesUsd"])))
    return {"measuredAt": int(time.time()), "rows": rows}


def digest_lp(now, text):
    lines = []
    for entry in now["rows"]:
        if entry["inside"]:
            lines.append(row("warn" if entry["near"] else "up", text["lpLine"].format(
                label=esc(entry["label"]), price=bold(fmt_usd(entry["price"])),
                low=fmt_usd(entry["low"]), high=fmt_usd(entry["high"]),
                at=round(entry["atPercent"]), down=round(entry["toLow"], 2),
                up=round(entry["toHigh"], 2), stock=round(entry["stockPercent"]),
                symbol=esc(entry["symbol0"]), value=fmt_usd(entry["valueUsd"]),
                fees=fmt_small(entry["feesUsd"]))))
        else:
            side = text["lpBelow"] if entry["price"] <= entry["low"] else text["lpAbove"]
            lines.append(row("down", text["lpLineOut"].format(
                label=esc(entry["label"]), price=bold(fmt_usd(entry["price"])), side=side,
                low=fmt_usd(entry["low"]), high=fmt_usd(entry["high"]),
                value=fmt_usd(entry["valueUsd"]), fees=fmt_small(entry["feesUsd"]))))
        lines[-1]["bar"] = {"at": entry["atPercent"], "inside": entry["inside"]}
    return lines


def evaluate_lp(cfg, now, state, text):
    """Out of range means no fees and no points, so both edges of that flip matter."""
    limit = cfg["thresholds"]["edgePercent"]
    flags = dict(state.get("flags", {}))
    alerts = []
    for row in now["rows"]:
        out_key = "out:" + row["label"]
        was_out = flags.get(out_key, False)
        is_out = not row["inside"]
        if is_out and not was_out:
            side = text["lpBelow"] if row["price"] <= row["low"] else text["lpAbove"]
            alerts.append(mark(text, "alarm") + " " + text["lpOut"].format(
                label=esc(row["label"]), side=side, price=bold(fmt_usd(row["price"])),
                low=fmt_usd(row["low"]), high=fmt_usd(row["high"])))
        elif was_out and not is_out:
            alerts.append(mark(text, "up") + " " + text["lpBack"].format(
                label=esc(row["label"]), price=bold(fmt_usd(row["price"])),
                at=round(row["atPercent"])))
        flags[out_key] = is_out

        edge_key = "edge:" + row["label"]
        nearest = min(row["toLow"], row["toHigh"])
        near = row["inside"] and nearest <= limit
        if near and not flags.get(edge_key, False):
            side = text["lpBelow"] if row["toLow"] <= row["toHigh"] else text["lpAbove"]
            alerts.append(mark(text, "warn") + " " + text["lpEdge"].format(
                label=esc(row["label"]), side=side, gap=round(nearest, 2),
                limit=limit, price=fmt_usd(row["price"]), fees=fmt_small(row["feesUsd"])))
        flags[edge_key] = near
    return alerts, flags


# --------------------------------------------------------------- alerting

def evaluate(cfg, now, state, text):
    """Return (alerts, new_flags). An alert fires only when a flag flips on."""
    th = cfg["thresholds"]
    flags = dict(state.get("flags", {}))
    alerts = []

    def flip(name, active, message):
        was = flags.get(name, False)
        flags[name] = active
        if active and not was:
            alerts.append(mark(text, "alarm") + " " + message)
        elif was and not active and cfg.get("alertOnRecovery", True):
            alerts.append(mark(text, "up") + " "
                          + text["recovered"].format(what=text["names"][name]))

    days = sorted(now["launchesByDay"])
    completed = [d for d in days if d != day_key(now["measuredAt"])]

    history = dict(state.get("launchesByDay", {}))
    history.update(now["launchesByDay"])
    recent = sorted(history)[-(th["launchesLowForDays"] + 1):]
    recent = [d for d in recent if d != day_key(now["measuredAt"])]
    low_streak = (
        len(recent) >= th["launchesLowForDays"]
        and all(history.get(d, 0) < th["launchesPerDayBelow"] for d in recent[-th["launchesLowForDays"]:])
    )
    flip("launchesDying", low_streak, text["launchesDying"].format(
        days=th["launchesLowForDays"], limit=th["launchesPerDayBelow"],
        values=", ".join("%s: %d" % (d, history.get(d, 0)) for d in recent[-th["launchesLowForDays"]:])))

    rev_history = dict(state.get("revenueByDay", {}))
    rev_history.update(now["revenueByDay"])
    last_rev_day = completed[-1] if completed else None
    if last_rev_day:
        value = rev_history.get(last_rev_day, 0)
        flip("revenueDead", value < th["revenueUsdPerDayBelow"],
             text["revenueDead"].format(day=last_rev_day, value=round(value),
                                        limit=th["revenueUsdPerDayBelow"]))

    # Measured from the last time burning actually moved, not from the last run:
    # running the watcher every few hours must not make a 24h stall invisible.
    prev_burn = state.get("burned")
    changed_at = state.get("burnChangedAt") or state.get("measuredAt")
    if prev_burn is not None and (now["burned"] - prev_burn) >= th["burnMinTokens"]:
        changed_at = now["measuredAt"]
    now["burnChangedAt"] = changed_at
    if changed_at:
        idle_hours = (now["measuredAt"] - changed_at) / 3600.0
        flip("burnStalled", idle_hours >= th["burnStalledHours"], text["burnStalled"].format(
            hours=round(idle_hours), delta=round(now["burned"] - (prev_burn or now["burned"]))))

    cap = now.get("topChildMcap", 0)
    flip("childHit", cap >= th["topChildMcapAbove"], text["childHit"].format(
        cap=fmt_usd(cap), symbol=now.get("topChildSymbol") or "?",
        limit=fmt_usd(th["topChildMcapAbove"])))

    return alerts, flags, history, rev_history


# --------------------------------------------------------------- presentation

def esc(value):
    """Telegram parses the message as HTML, and a token symbol is attacker-chosen text."""
    return html.escape(str(value), quote=False)


def bold(value):
    return "<b>" + esc(value) + "</b>"


def mark(text, kind):
    """Telegram has no coloured text. A coloured circle in front of the line is the
    closest thing to it, and it survives copy-paste and notification previews."""
    return text.get("marks", {}).get(kind, "")


def sign_of(change, flat="flat"):
    """Which way a number moved, as a marker name. Nothing to compare against is
    its own answer -- it is not neutral, it is unknown."""
    if not isinstance(change, (int, float)):
        return "info"
    if change > 0:
        return "up"
    if change < 0:
        return "down"
    return flat


def row(kind, body, logo=None):
    """One line of a digest. The text carries the words, the kind carries the colour,
    and the logo is a URL the picture digest can draw; the text message ignores it."""
    return {"kind": kind, "text": body, "logo": logo}


def as_text(lines, text):
    return "\n".join(("%s %s" % (mark(text, line["kind"]), line["text"])).strip()
                     for line in lines)


def fmt_change(change):
    return ("%+.1f%%" % change) if isinstance(change, (int, float)) else "-"


def fmt_usd(value):
    value = float(value or 0)
    if value >= 1_000_000:
        return "$%.2fM" % (value / 1_000_000)
    if value >= 1000:
        return "$%s" % format(int(round(value)), ",")
    if value >= 1:
        return "$%.2f" % value
    return "$%.6f" % value


def digest(now, text, previous_price=None):
    days = sorted(now["launchesByDay"])
    today = day_key(now["measuredAt"])
    completed = [d for d in days if d != today]
    last = completed[-1] if completed else today

    # The day line is marked against the day before it, the market line against the
    # price at the last run: a number on its own says nothing about direction.
    revenue = now["revenueByDay"].get(last, 0)
    earlier = [d for d in completed if d < last]
    revenue_before = now["revenueByDay"].get(earlier[-1]) if earlier else None
    day_change = (revenue - revenue_before) if revenue_before is not None else None
    price_change = (now["price"] - previous_price) if previous_price else None

    return [
        row(sign_of(day_change), text["digestDay"].format(
            day=last, launches=now["launchesByDay"].get(last, 0),
            revenue=bold(fmt_usd(revenue)))),
        row("info", text["digestBurn"].format(
            burned=format(int(round(now["burned"])), ","),
            burnedPercent=round(now["burnedPercent"], 2))),
        row("info", text["digestChild"].format(
            childSymbol=esc(now.get("topChildSymbol") or "-"),
            child=fmt_usd(now.get("topChildMcap", 0)))),
        row(sign_of(price_change), text["digestMarket"].format(
            price=bold(fmt_usd(now["price"])), cap=fmt_usd(now["marketCap"]),
            liquidity=fmt_usd(now["liquidity"])), logo=now.get("imageUrl")),
    ]


def strip_tags(message):
    return re.sub(r"</?b>", "", message)


def draw_card(results, header, log):
    """The picture digest is optional scenery: it needs Pillow, and the engine itself
    needs nothing but the standard library. If it cannot be drawn, the text goes."""
    try:
        import digest_card
    except Exception as exc:  # noqa: BLE001
        log("card: not available (%s), sending text" % exc)
        return None
    return digest_card.render(results, header,
                              os.path.join(BASE_DIR, "state", "digest.png"), log)


def telegram_photo(token, chat_id, path, caption, log):
    """sendPhoto needs multipart/form-data, which the stdlib will not build for us."""
    boundary = "----chain-sentry-%s" % os.urandom(8).hex()
    body = bytearray()
    for key, value in (("chat_id", chat_id), ("caption", caption[:1024]),
                       ("parse_mode", "HTML")):
        body += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                 % (boundary, key, value)).encode()
    with open(path, "rb") as handle:
        blob = handle.read()
    body += ('--%s\r\nContent-Disposition: form-data; name="photo"; '
             'filename="digest.png"\r\nContent-Type: image/png\r\n\r\n' % boundary).encode()
    body += blob + ("\r\n--%s--\r\n" % boundary).encode()

    request = urllib.request.Request(
        "https://api.telegram.org/bot%s/sendPhoto" % token, data=bytes(body),
        headers={"content-type": "multipart/form-data; boundary=" + boundary,
                 "user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            out = json.load(response)
        if out.get("ok"):
            log("telegram: picture sent")
            return True
        log("telegram: picture rejected -- %s" % out.get("description"))
    except Exception as exc:  # noqa: BLE001
        log("telegram: picture failed -- %s" % exc)
    return False


def telegram(token, chat_id, message, log):
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    payload = {"chat_id": chat_id, "text": message, "disable_web_page_preview": True,
               "parse_mode": "HTML"}
    try:
        out = http_json(url, payload, retries=2)
        if out.get("ok"):
            log("telegram: sent")
            return True
        log("telegram: rejected -- %s" % out.get("description"))
        # A message refused over its markup should still arrive: the numbers in it
        # matter more than the bold. Send it again as plain text.
        payload.pop("parse_mode")
        payload["text"] = strip_tags(message)
        out = http_json(url, payload, retries=2)
        if out.get("ok"):
            log("telegram: sent as plain text")
            return True
        log("telegram: rejected again -- %s" % out.get("description"))
    except Exception as exc:  # noqa: BLE001
        log("telegram: failed -- %s" % exc)
    return False


# --------------------------------------------------------------- main

def process_one(cfg_path, log):
    """Run one config. Returns its digest text, its alerts and the state to be written."""
    path = cfg_path if os.path.isabs(cfg_path) else os.path.join(BASE_DIR, cfg_path)
    with open(path, "r", encoding="utf-8") as handle:
        cfg = json.load(handle)

    lang_path = os.path.join(BASE_DIR, "lang", "metrics.%s.json" % cfg.get("language", "en"))
    with open(lang_path, "r", encoding="utf-8") as handle:
        text = json.load(handle)

    state_path = os.path.join(BASE_DIR, cfg["stateFile"])
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    state = {}
    if os.path.isfile(state_path):
        with open(state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)

    log("--- %s ---" % cfg["name"])
    first_run = not state.get("baseline")
    profile = cfg.get("profile", "launchpad")

    if profile == "tokens":
        now = measure_tokens(cfg, log)
        log("watchlist: %d tokens, %d priced" % (
            len(now["rows"]), sum(1 for r in now["rows"] if r["found"])))
        lines = digest_tokens(now, text)
        alerts, flags = ([], {}) if first_run else evaluate_tokens(cfg, now, state, text)
        state_out = {"baseline": True, "measuredAt": now["measuredAt"], "flags": flags}
    elif profile == "lp":
        now = measure_lp(cfg, Rpc(cfg["rpc"]), log)
        lines = digest_lp(now, text)
        alerts, flags = ([], {}) if first_run else evaluate_lp(cfg, now, state, text)
        state_out = {"baseline": True, "measuredAt": now["measuredAt"], "flags": flags}
    elif profile == "wallet":
        now = measure_wallet(cfg, log, state.get("knownTokens"))
        log("holdings: %d worth %s, %d spam tokens ignored" % (
            len(now["holdings"]), fmt_usd(now["totalUsd"]), now["spamCount"]))
        lines = digest_wallet(now, text, state.get("totalUsd"))
        alerts, flags = ([], {}) if first_run else evaluate_wallet(cfg, now, state, text)
        state_out = {
            "baseline": True,
            "measuredAt": now["measuredAt"],
            "totalUsd": now["totalUsd"],
            "knownTokens": now["knownTokens"] or state.get("knownTokens") or [],
            "flags": flags,
        }
    else:
        rpc = Rpc(cfg["rpc"])
        # The first run reaches further back so the day history and the list of coins
        # the launchpad produced start out populated instead of empty.
        days_back = cfg["seedDays"] if first_run else cfg["windowDays"]
        now = measure(cfg, rpc, log, days_back)
        cap, symbol, known_children = top_child(state, now["childTokens"], cfg["watch"]["childScanLimit"])
        now["topChildMcap"] = cap
        now["topChildSymbol"] = symbol

        log("launches: %s" % (", ".join("%s=%d" % kv for kv in sorted(now["launchesByDay"].items())) or "none"))
        log("revenue:  %s" % (", ".join("%s=$%d" % (k, round(v)) for k, v in sorted(now["revenueByDay"].items())) or "none"))
        log("burned:   %s tokens (%.2f%% of supply)" % (format(int(now["burned"]), ","), now["burnedPercent"]))
        log("children: %d known, biggest %s at %s" % (len(known_children), symbol or "-", fmt_usd(cap)))
        log("market:   price %s, cap %s, liquidity %s" % (
            fmt_usd(now["price"]), fmt_usd(now["marketCap"]), fmt_usd(now["liquidity"])))

        lines = digest(now, text, state.get("lastPrice"))
        if first_run:
            alerts, flags = [], {}
            history = dict(now["launchesByDay"])
            rev_history = dict(now["revenueByDay"])
        else:
            alerts, flags, history, rev_history = evaluate(cfg, now, state, text)
        state_out = {
            "baseline": True,
            "measuredAt": now["measuredAt"],
            "burnChangedAt": now.get("burnChangedAt"),
            "block": now["block"],
            "burned": now["burned"],
            "flags": flags,
            "launchesByDay": trim_days(history, cfg["keepDays"]),
            "revenueByDay": trim_days(rev_history, cfg["keepDays"]),
            "childTokens": known_children[:cfg["watch"]["childScanLimit"]],
            "lastPrice": now["price"],
            "lastTopChildMcap": cap,
        }

    if first_run:
        log(text["baselineWritten"])

    return {
        "name": cfg["name"],
        "body": as_text(lines, text),
        "lines": lines,
        "profile": profile,
        "alerts": alerts,
        "firstRun": first_run,
        "statePath": state_path,
        "state": state_out,
        "text": text,
        "notify": cfg["notify"],
    }


def main():
    parser = argparse.ArgumentParser(description="chain-sentry metrics engine")
    parser.add_argument("--config", action="append", required=True,
                        help="config file; repeat the flag to fold several into one message")
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--alerts-only", action="store_true",
                        help="stay silent unless something crossed a threshold")
    parser.add_argument("--dry-run", action="store_true", help="measure and log, never send")
    parser.add_argument("--card", action="store_true",
                        help="send the digest as a picture, with each project's own logo")
    parser.add_argument("--log", default="state/metrics.log")
    args = parser.parse_args()

    log_path = args.log if os.path.isabs(args.log) else os.path.join(BASE_DIR, args.log)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    lines = []

    def log(message):
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        line = "%s  %s" % (stamp, message)
        lines.append(line)
        print(line)

    load_env_file(args.env_file)
    log("=== run over %d config(s) ===" % len(args.config))

    results, failed = [], []
    for cfg_path in args.config:
        try:
            results.append(process_one(cfg_path, log))
        except Exception as exc:  # noqa: BLE001 - one broken config must not sink the rest
            log("FAILED %s: %s" % (cfg_path, exc))
            failed.append(os.path.basename(cfg_path))

    if not results:
        log("nothing measured")
        write_log(log_path, lines)
        return 1

    text = results[0]["text"]
    alerts = [(r["name"], a) for r in results for a in r["alerts"]]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    header = mark(text, "digest") + " " + bold(text["combinedDigestHeader"].format(date=stamp))
    alert_blocks, digest_blocks, notes = [], [], []
    if alerts:
        alert_blocks.append(mark(text, "alarm") + " " + bold(text["combinedAlertHeader"]))
        alert_blocks.extend("%s\n%s" % (bold(name), alert) for name, alert in alerts)
    if alerts or not args.alerts_only:
        digest_blocks.append(header)
        digest_blocks.extend("%s\n%s" % (bold(r["name"]), r["body"]) for r in results)
        new_ones = [r["name"] for r in results if r["firstRun"]]
        if new_ones:
            notes.append(mark(text, "info") + " "
                         + text["baselineNote"].format(names=esc(", ".join(new_ones))))
    if failed and (alert_blocks or digest_blocks):
        notes.append(mark(text, "alarm") + " "
                     + text["someFailed"].format(names=esc(", ".join(failed))))

    message = "\n\n".join(alert_blocks + digest_blocks + notes)
    if not message:
        log(text["nothingChanged"])

    if message:
        if args.dry_run:
            log("dry run, message not sent:")
            log(message)
        else:
            token = os.environ.get(results[0]["notify"]["tokenEnv"], "")
            chat = os.environ.get(results[0]["notify"]["chatEnv"], "")
            if not (token and chat):
                log("telegram: credentials missing, message not sent")
                log(message)
            else:
                card = None
                if args.card and digest_blocks:
                    card = draw_card(results, strip_tags(header), log)
                if card:
                    # An alarm still goes as text: it has to be readable in the
                    # notification preview, where a photo shows nothing but a caption.
                    if alert_blocks:
                        telegram(token, chat, "\n\n".join(alert_blocks), log)
                    if not telegram_photo(token, chat, card,
                                          "\n\n".join([header] + notes), log):
                        telegram(token, chat, message, log)
                else:
                    telegram(token, chat, message, log)

    if args.dry_run:
        # A rehearsal must not move the baseline, or the next real run would compare
        # against a state nobody was told about.
        log("dry run: state left untouched")
    else:
        for result in results:
            with open(result["statePath"], "w", encoding="utf-8") as handle:
                json.dump(result["state"], handle, ensure_ascii=False, indent=2)

    write_log(log_path, lines)
    return 0 if not failed else 2


def trim_days(mapping, keep):
    days = sorted(mapping)[-keep:]
    return {d: mapping[d] for d in days}


def write_log(path, lines):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
