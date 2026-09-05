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
    revenue    what a protocol earns per day (DefiLlama), judged on a multi-day average
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

    def logs(self, address, topic, from_block, to_block, step=40000, topics=None):
        """eth_getLogs over a range, split into chunks a public node will accept.

        `topics` passes the whole filter through when the caller needs more than
        topic0 -- transfers *from* one address, say. A node that refuses the range
        gets a smaller one, down to 1000 blocks: public nodes cap the answer by size,
        so a busy contract like WETH needs a much shorter reach than a quiet one.
        """
        out = []
        start = from_block
        while start <= to_block:
            end = min(start + step - 1, to_block)
            try:
                chunk = self.call("eth_getLogs", [{
                    "address": address,
                    "topics": topics or [topic],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                }])
            except RuntimeError:
                if step <= 1000:
                    raise
                step = max(1000, step // 4)
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

def dexscreener_tokens(addresses, batch_size=5, chain=None):
    """Best pair per token address, keyed by lowercase address.

    The endpoint caps how many PAIRS it returns per call, not how many tokens, so a
    token with many pools crowds its neighbours out of the answer entirely. Small
    batches cost more requests and are the only way to get every token priced.

    `chain` matters more than it looks. An address is only unique within one chain,
    and the same twenty hex bytes elsewhere can be a completely different token: on
    2026-09-04 CASHCAT on Robinhood Chain was priced at 7.0e26 dollars a coin, because
    a namesake address on another chain carried a two-billion-dollar pool and won the
    "deepest liquidity" contest. Naming the chain removes the whole class of error.
    """
    best = {}
    addresses = [a for a in addresses if a]
    for i in range(0, len(addresses), batch_size):
        batch = ",".join(addresses[i:i + batch_size])
        try:
            data = http_json("https://api.dexscreener.com/latest/dex/tokens/" + batch, retries=2)
        except Exception:  # noqa: BLE001 - price data is best effort
            continue
        by_token = {}
        for pair in (data.get("pairs") or []):
            if chain and str(pair.get("chainId", "")).lower() != chain.lower():
                continue
            by_token.setdefault(pair["baseToken"]["address"].lower(), []).append(pair)
        for key, pairs in by_token.items():
            pairs = reject_outlier_pairs(pairs)
            if not pairs:
                continue
            deepest = max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0)
            change = deepest.get("priceChange") or {}
            txns24 = (deepest.get("txns") or {}).get("h24") or {}
            volume = deepest.get("volume") or {}
            best[key] = {
                "symbol": deepest["baseToken"]["symbol"],
                "price": float(deepest.get("priceUsd") or 0),
                "liquidity": (deepest.get("liquidity") or {}).get("usd") or 0,
                "marketCap": deepest.get("marketCap") or deepest.get("fdv") or 0,
                "volume24": volume.get("h24") or 0,
                "change24": change.get("h24"),
                # These windows turn "up 30% on the day" into something to act on:
                # whether it is still climbing or already rolled over.
                "change1": change.get("h1"),
                "change6": change.get("h6"),
                "buys24": txns24.get("buys") or 0,
                "sells24": txns24.get("sells") or 0,
                "pairCreatedAt": deepest.get("pairCreatedAt"),
                "url": deepest.get("url"),
                # Kept for the picture digest: the project's own logo.
                "imageUrl": (deepest.get("info") or {}).get("imageUrl"),
                "liquidityTotal": sum((p.get("liquidity") or {}).get("usd") or 0
                                      for p in pairs),
                "poolCount": len(pairs),
            }
    return best


def reject_outlier_pairs(pairs, factor=5.0):
    """Drop pools quoting a price the rest of the market disagrees with.

    Deepest liquidity is the usual way to pick the honest pool, and it fails on a
    junk pool that also reports junk depth. CASHCAT on Robinhood Chain had five
    Uniswap pools around $0.255 and one "robinvista" pool quoting 7.0e26 dollars
    against a claimed two billion of liquidity -- and the deepest-pool rule handed
    the wallet a total of $1.6e29. The median of the pools is the sober opinion;
    anything more than a factor away from it is not a price, it is a broken feed.

    With one or two pools there is nothing to compare against, so nothing is dropped.
    """
    priced = [(float(p.get("priceUsd") or 0), p) for p in pairs]
    priced = [(px, p) for px, p in priced if px > 0]
    if len(priced) < 3:
        return [p for _, p in priced] or list(pairs)
    ordered = sorted(px for px, _ in priced)
    median = ordered[len(ordered) // 2]
    if median <= 0:
        return [p for _, p in priced]
    return [p for px, p in priced if median / factor <= px <= median * factor]


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

    # The fuel behind the buyback, and the number the revenue metric above cannot see.
    # Platform revenue counts what the launchpad takes off other people's coins; the
    # locker also hands over the fees of the token's OWN pool, and over 31.08-05.09
    # that was 3.35 of the 4.78 ETH that went into buying and burning. Measured where
    # it actually leaves: native quote asset out of the locker.
    fuel = dict((day, 0.0) for day in calendar)
    for entry in rpc.logs(quote_native, TOPIC_TRANSFER, from_block, latest,
                          topics=[TOPIC_TRANSFER, pad_addr(locker)]):
        day = day_key(ts_of(int(entry["blockNumber"], 16)))
        fuel[day] = fuel.get(day, 0.0) + uint_of(entry["data"][2:66]) / 1e18

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
        "fuelByDay": {k: round(v, 4) for k, v in fuel.items()},
        "burned": burned,
        "burnedPercent": (burned / supply * 100) if supply else 0,
        "childTokens": sorted(child_tokens),
        "price": own.get("price", 0),
        "marketCap": own.get("marketCap", 0),
        "liquidity": own.get("liquidityTotal", own.get("liquidity", 0)),
        "volume24": own.get("volume24", 0),
    }


TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def discover_by_logs(rpc, address, from_block, log):
    """Find tokens on a chain with no explorer to ask -- by reading the chain itself.

    Robinhood Chain's Blockscout answers a script with 403, so the FOMO wallet was
    watched through a hand-written list of three tokens: anything bought after the
    list was written did not exist as far as the watcher was concerned. It does now.
    Every ERC-20 credits the recipient in an indexed topic, so one filtered
    eth_getLogs names every token this address was ever sent.

    Returns (tokens, scanned_to). The cursor means later runs read only new blocks.
    """
    latest = int(rpc.call("eth_blockNumber", []), 16)
    if from_block > latest:
        return [], latest
    padded = "0x" + "0" * 24 + address.lower().replace("0x", "")
    query = {"topics": [TOPIC_TRANSFER, None, padded], "fromBlock": hex(from_block)}
    try:
        # This node answers an open-ended range in one call when the topic filter is
        # narrow, which it is -- one recipient. Cheaper than a thousand windows.
        entries = rpc.call("eth_getLogs", [dict(query, toBlock=hex(latest))])
    except RuntimeError as exc:
        log("discovery: one-shot scan refused (%s), walking in windows" % str(exc)[:80])
        entries, start, step = [], from_block, 100000
        while start <= latest:
            end = min(start + step - 1, latest)
            try:
                entries += rpc.call("eth_getLogs", [dict(query, fromBlock=hex(start),
                                                         toBlock=hex(end))])
            except RuntimeError:
                if step <= 5000:
                    raise
                step = max(5000, step // 2)
                continue
            start = end + 1
    found = []
    for entry in entries:
        token = str(entry.get("address", "")).lower()
        if token and token not in found:
            found.append(token)
    return found, latest


def measure_wallet(cfg, log, known=None, scanned_to=0, discovered=None):
    """Profile 'wallet': what an address actually holds, spam filtered out by value.

    A Base wallet accumulates hundreds of airdropped tokens nobody asked for. Counting
    them as holdings makes every number meaningless, so anything under `minUsd` is
    dropped -- and how many were dropped is itself reported, because a sudden jump in
    spam is worth seeing.
    """
    w = cfg["watch"]
    address = w["address"]

    # A chain whose explorer will not talk to a script is still watchable: name the
    # tokens in the config and every balance still comes from the chain, which is where
    # it should come from anyway. Robinhood Chain's Blockscout sits behind Cloudflare
    # and answers with 403, so this is not a hypothetical case.
    configured = [{"symbol": t.get("symbol", "?"), "address": t["address"],
                   "decimals": t.get("decimals", 18)} for t in w.get("tokens", [])]
    if configured:
        seen_known = {k["address"].lower() for k in (known or [])}
        known = list(known or []) + [t for t in configured
                                     if t["address"].lower() not in seen_known]

    # No explorer does not have to mean no discovery. Read the transfer log instead,
    # so a coin bought today shows up tonight without anyone editing the config.
    # `discovered` is kept apart from `knownTokens` on purpose: knownTokens is rebuilt
    # each run from what is worth more than minUsd, so a coin that dips under a dollar
    # would fall out of it and -- the cursor having moved past its transfer -- never be
    # found again. This list forgets nothing.
    discovered = list(discovered or [])
    rebased = False
    if not w.get("explorer") and w.get("rpc") and w.get("discover", True):
        try:
            rpc = Rpc(w["rpc"])
            fresh, scanned_to = discover_by_logs(rpc, address, scanned_to, log)
            seen_any = {k["address"].lower() for k in (known or [])} | {
                d["address"].lower() for d in discovered}
            cache, added = {}, []
            for token in fresh:
                if token in seen_any:
                    continue
                symbol, decimals = token_meta(rpc, token, cache)
                discovered.append({"symbol": symbol, "address": token, "decimals": decimals})
                seen_any.add(token)
                added.append(symbol)
            if added:
                log("discovery: %d new token(s) off the chain -- %s"
                    % (len(added), ", ".join(added)))
                # The total is about to jump because the watcher learned to see more,
                # not because the wallet grew. Announcing that as a move would be a lie.
                rebased = True
            seen_known = {k["address"].lower() for k in (known or [])}
            known = list(known or []) + [d for d in discovered
                                         if d["address"].lower() not in seen_known]
        except Exception as exc:  # noqa: BLE001 - discovery is a bonus, never a blocker
            log("discovery: log scan failed (%s), using the known list" % str(exc)[:100])

    entries, complaint, from_cache = None, "", False
    if w.get("explorer"):
        url = "%s?module=account&action=tokenlist&address=%s" % (w["explorer"], address)
        # Blockscout answers a rate limit with HTTP 200 and an empty result, so it looks
        # like success to every transport check. Only the message says otherwise.
        for attempt in range(5):
            listing = http_json(url, retries=1)
            entries = listing.get("result")
            if isinstance(entries, list):
                break
            complaint = str(listing.get("message") or listing)[:120]
            entries = None
            log("explorer said '%s', waiting" % complaint)
            time.sleep(8 * (attempt + 1))
    else:
        complaint = "no explorer configured for this chain"

    if entries is None:
        # Discovery is the ONLY thing the explorer is needed for -- every balance is
        # read from the chain anyway. So a rate limit costs us new tokens, not the
        # whole report: fall back to the token list this wallet was already known to
        # hold and say so, rather than dropping the wallet out of the digest entirely.
        if known:
            log("%s; reading %d tokens straight from the chain" % (complaint, len(known))
                if not w.get("explorer") else
                "explorer unavailable (%s); reusing %d known tokens" % (complaint, len(known)))
            from_cache = True
            entries = [{"type": "ERC-20", "symbol": k["symbol"], "decimals": str(k.get("decimals", 18)),
                        "contractAddress": k["address"], "balance": "1",
                        "placeholder": True} for k in known]
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
            "placeholder": bool(item.get("placeholder")),
        })

    prices = dexscreener_tokens([h["address"] for h in held], chain=w.get("chain"))
    for holding in held:
        info = prices.get(holding["address"], {})
        holding["price"] = info.get("price", 0)
        holding["liquidity"] = info.get("liquidityTotal", info.get("liquidity", 0))
        holding["change24"] = info.get("change24")
        holding["imageUrl"] = info.get("imageUrl")
        # The rest of the market picture rides along so an alert can show the coin
        # properly instead of just naming it. Cheap: it came in the same response.
        for extra in ("marketCap", "volume24", "change1", "change6", "buys24",
                      "sells24", "pairCreatedAt", "url", "poolCount"):
            holding[extra] = info.get(extra)
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
    real, ghosts, empty, unread = [], [], 0, []
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
            if holding.get("placeholder"):
                # There is no explorer number to fall back on here: the balance is a
                # stand-in of 1 wei, and reporting it would put the coin in the digest
                # at zero dollars, which reads as "sold" rather than "not answered".
                # A dropped node must not be able to make money look like it vanished.
                unread.append(holding["symbol"])
                continue
            real.append(holding)
            continue
        if onchain <= 0:
            # An explorer claiming a balance the chain does not have is worth saying out
            # loud. A configured token simply sitting at zero is not news, it just means
            # the wallet does not hold it right now.
            if not from_cache:
                ghosts.append(holding["symbol"])
            empty += 1
            continue
        holding["balance"] = onchain
        holding["usd"] = onchain * holding["price"]
        if holding["usd"] >= w["minUsd"]:
            real.append(holding)
    if ghosts:
        log("explorer listed balances the chain does not have: %s" % ", ".join(ghosts))
    if unread:
        log("node would not answer for %d token(s), left out of the total: %s"
            % (len(unread), ", ".join(unread)))

    real.sort(key=lambda h: -h["usd"])
    return {
        "measuredAt": int(time.time()),
        "fromCache": from_cache,
        "knownTokens": [{"symbol": h["symbol"], "address": h["address"],
                         "decimals": h.get("decimals", 18)} for h in real],
        "discoveredTokens": discovered,
        "scannedToBlock": scanned_to,
        "partial": bool(unread),
        "rebased": rebased,
        "holdings": real,
        "totalUsd": sum(h["usd"] for h in real),
        "tokenCount": len(held),
        "spamCount": max(0, len(held) - len(real) - empty),
    }


def digest_wallet(now, text, previous_total=None):
    change = (now["totalUsd"] - previous_total) if previous_total else None
    lines = [row(sign_of(change), text["walletTotal"].format(
        total=num(fmt_usd(now["totalUsd"])), kept=len(now["holdings"]),
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

    # An incomplete measurement cannot be compared against a complete one.
    if previous and previous > 0 and not now.get("partial") and not now.get("rebased"):
        move = (now["totalUsd"] - previous) / previous * 100
        if abs(move) >= th["totalMovePercent"]:
            alerts.append(mark(text, sign_of(move)) + " " + text["walletMoved"].format(
                move=round(move, 1), was=fmt_usd(previous), now=num(fmt_usd(now["totalUsd"]))))

    # A total hides the thing worth knowing. On 2026-09-04 this wallet held PONS up 32%
    # and Index down over the same day; the two cancelled to -1.8% and the watcher said
    # nothing at all. So every holding is now judged on its own move as well.
    token_limit = th.get("tokenMovePercent")
    for holding in now["holdings"] if token_limit else []:
        change = holding.get("change24")
        if change is None:
            continue
        loud = abs(change) >= token_limit
        key = "moved:%s:%s" % (holding["address"], "up" if change > 0 else "down")
        opposite = "moved:%s:%s" % (holding["address"], "down" if change > 0 else "up")
        # A coin that keeps sitting above the line must not be re-announced every run;
        # it is re-armed once it comes back under, or turns the other way.
        flags.pop(opposite, None)
        if loud and not flags.get(key):
            alerts.append(mark(text, sign_of(change)) + " " + text["walletTokenMoved"].format(
                symbol=esc(holding["symbol"]), change=num(fmt_change(change)),
                usd=fmt_usd(holding["usd"]))
                + "\n" + coin_card(holding, text, held_usd=holding['usd']))
        flags[key] = loud
    for key in [k for k in flags if k.startswith("moved:")]:
        if not flags.get(key):
            flags.pop(key, None)

    # Liquidity draining under a holding is the early warning a price chart gives too late.
    thin = [h for h in now["holdings"] if 0 < h["liquidity"] < th["liquidityBelowUsd"]]
    for holding in thin:
        key = "thin:" + holding["address"]
        if not flags.get(key):
            alerts.append(mark(text, "alarm") + " " + text["walletThin"].format(
                symbol=esc(holding["symbol"]), liq=fmt_usd(holding["liquidity"]),
                limit=fmt_usd(th["liquidityBelowUsd"]), usd=fmt_usd(holding["usd"]))
                + "\n" + coin_card(holding, text, held_usd=holding['usd']))
        flags[key] = True
    for key in [k for k in flags if k.startswith("thin:")]:
        if key not in ["thin:" + h["address"] for h in thin]:
            flags.pop(key, None)

    return alerts, flags


def measure_tokens(cfg, log):
    """Profile 'tokens': a named watchlist, whatever chain each one lives on.

    Each token is asked for on its own chain. Without that, an address is only
    unique within one chain and a namesake elsewhere can win the deepest-pool
    contest: that is how CASHCAT on Robinhood Chain once got priced at 7.0e26
    dollars. The wallet profile has named its chain since 04.09; this one did
    not, and it watches Robinhood Chain coins, where namesakes are common.
    `chain` can be set once for the watchlist or per token.
    """
    entries = cfg["watch"]["tokens"]
    default_chain = cfg["watch"].get("chain")
    rows = []
    for entry in entries:
        address = entry["address"].lower()
        chain = entry.get("chain", default_chain)
        info = dexscreener_tokens([address], batch_size=1, chain=chain).get(address, {})
        rows.append(dict(info, **{
            "label": entry.get("label") or info.get("symbol") or entry["address"][:10],
            "address": entry["address"].lower(),
            "price": info.get("price", 0),
            "change24": info.get("change24"),
            "liquidity": info.get("liquidityTotal", info.get("liquidity", 0)),
            "marketCap": info.get("marketCap", 0),
            "found": bool(info),
            "imageUrl": info.get("imageUrl"),
            "alertBelowUsd": entry.get("alertBelowUsd"),
        }))
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
                    price=num(fmt_usd(row["price"])))
                    + "\n" + coin_card(row, text))
                flags[key] = True
        # A price level the user is waiting for. Fires once on the way down and
        # rearms only after the price climbs 2% clear of the line, so a coin
        # hovering on it does not ring all night.
        floor = row.get("alertBelowUsd")
        if floor and row["price"] > 0:
            below_key = "below:" + row["address"]
            if row["price"] <= floor and not flags.get(below_key):
                alerts.append(mark(text, "alarm") + " " + text["tokenBelow"].format(
                    label=esc(row["label"]), price=num(fmt_usd(row["price"])),
                    limit=num(fmt_usd(floor)))
                    + "\n" + coin_card(row, text))
                flags[below_key] = True
            elif row["price"] > floor * 1.02:
                flags[below_key] = False

        thin_key = "thin:" + row["address"]
        is_thin = 0 < row["liquidity"] < th["liquidityBelowUsd"]
        if is_thin and not flags.get(thin_key):
            alerts.append(mark(text, "alarm") + " " + text["tokenThin"].format(
                label=esc(row["label"]), liq=fmt_usd(row["liquidity"]),
                limit=fmt_usd(th["liquidityBelowUsd"]))
                + "\n" + coin_card(row, text))
        flags[thin_key] = is_thin

    # Day-scoped move flags would pile up forever; keep only today's.
    today = day_key(now["measuredAt"])
    flags = {k: v for k, v in flags.items() if not k.startswith("move:") or k.endswith(today)}
    return alerts, flags


def measure_revenue(cfg, log):
    """Profile 'revenue': what a protocol earns per day, read from DefiLlama.

    Reading this off the chain would mean tracking every fee contract a launchpad
    deploys, and it deploys one per coin. DefiLlama already normalises that, so this
    profile takes the number and does the judging here.

    Only COMPLETE days count. The running day is a fraction of itself, and comparing
    it against a threshold would report a collapse every morning and a recovery every
    night. The average smooths the rest: a single quiet day is noise, three in a row
    is a trend.
    """
    w = cfg["watch"]
    span = int(w.get("averageDays", 3))
    url = "https://api.llama.fi/summary/fees/%s?dataType=%s" % (
        urllib.parse.quote(w["protocol"]), w.get("dataType", "dailyRevenue"))
    chart = http_json(url).get("totalDataChart") or []
    days = {}
    for point in chart:
        if isinstance(point, (list, tuple)) and len(point) >= 2:
            days[day_key(point[0])] = float(point[1] or 0)

    today = day_key(time.time())
    complete = sorted(d for d in days if d < today)
    if not complete:
        raise RuntimeError("DefiLlama returned no completed day for " + w["protocol"])

    window = complete[-span:]
    average = sum(days[d] for d in window) / len(window)
    peak_day = max(complete, key=lambda d: days[d])
    latest = complete[-1]
    stale_days = (dt.datetime.strptime(today, "%Y-%m-%d")
                  - dt.datetime.strptime(latest, "%Y-%m-%d")).days

    log("revenue: %s last complete day %s = $%s, %d-day average $%s, peak $%s on %s" % (
        w["protocol"], latest, format(round(days[latest]), ","), len(window),
        format(round(average), ","), format(round(days[peak_day]), ","), peak_day))

    return {
        "measuredAt": int(time.time()),
        "label": w.get("label") or w["protocol"],
        "latestDay": latest,
        "latestValue": days[latest],
        "average": average,
        "windowDays": len(window),
        "window": [(d, days[d]) for d in window],
        "peak": days[peak_day],
        "peakDay": peak_day,
        "staleDays": stale_days,
        "buybackShare": w.get("buybackShare"),
    }


def digest_revenue(now, text):
    share = now.get("buybackShare")
    buyback = (text["revenueBuyback"].format(buyback=fmt_usd(now["average"] * share))
               if share else "")
    off_peak = 0 if not now["peak"] else (1 - now["average"] / now["peak"]) * 100
    # "info", not "digest": the card's palette has no colour for the latter, and a
    # grey line reads as a dead one.
    return [row("info", text["digestRevenue"].format(
        label=esc(now["label"]), day=now["latestDay"], value=num(fmt_usd(now["latestValue"])),
        days=now["windowDays"], average=num(fmt_usd(now["average"])),
        peak=fmt_usd(now["peak"]), peakDay=now["peakDay"], offPeak=round(off_peak),
        buyback=buyback))]


def evaluate_revenue(cfg, now, state, text):
    """Alerts on the AVERAGE crossing a line, never on one day's number."""
    th = cfg["thresholds"]
    flags = dict(state.get("flags", {}))
    alerts = []

    def flip(name, active, message, kind="alarm"):
        was = flags.get(name, False)
        flags[name] = active
        if active and not was:
            alerts.append(mark(text, kind) + " " + message)
        elif was and not active and cfg.get("alertOnRecovery", True):
            alerts.append(mark(text, "up") + " "
                          + text["recovered"].format(what=text["names"][name]))

    average, alarm_at = now["average"], th["alarmBelowUsd"]
    warn_at = th["warnBelowUsd"]
    off_peak = 0 if not now["peak"] else (1 - average / now["peak"]) * 100
    detail = ", ".join("%s $%s" % (d, format(round(v), ",")) for d, v in now["window"])

    # Three states, not two flags. Two independent booleans would announce "back to
    # normal" on the way up from broken to merely sliding, which is not normal.
    level = "broken" if average < alarm_at else ("sliding" if average < warn_at else "ok")
    was = flags.get("revenueLevel", "ok")
    flags["revenueLevel"] = level
    if level != was:
        if level == "broken":
            alerts.append(mark(text, "alarm") + " " + text["revenueBroken"].format(
                label=esc(now["label"]), days=now["windowDays"],
                average=num(fmt_usd(average)), limit=fmt_usd(alarm_at),
                offPeak=round(off_peak), detail=detail))
        elif level == "sliding":
            alerts.append(mark(text, "warn") + " " + text["revenueSliding"].format(
                label=esc(now["label"]), days=now["windowDays"],
                average=num(fmt_usd(average)), limit=fmt_usd(warn_at),
                offPeak=round(off_peak), detail=detail))
        elif cfg.get("alertOnRecovery", True):
            alerts.append(mark(text, "up") + " "
                          + text["recovered"].format(what=text["names"]["revenueBroken"]))
    # A source that stops publishing looks exactly like a protocol that keeps earning.
    flip("revenueStale", now["staleDays"] > int(th.get("staleAfterDays", 2)),
         text["revenueStale"].format(label=esc(now["label"]), day=now["latestDay"],
                                     days=now["staleDays"]), kind="warn")
    return alerts, flags


SEL_LAUNCHER = "0x16eebd1e"  # launcher() -- only coins born on the launchpad answer it


def launchpad_coins(rpc, token, candidates, log):
    """Keep the coins the launchpad made, drop whatever they are priced against.

    A fee event names both sides of the pool, so every quote asset lands in the same
    bag as the coin: cbDOGE -- Coinbase's wrapped Dogecoin, nothing to do with this
    launchpad -- sat there at a $9.4M cap and tripped the "the launchpad finally has
    a hit" alarm. A coin from the launchpad answers launcher() with the launcher's
    address; everything else reverts. Unreadable answer on the watched token -> keep
    the whole list, the same as before this check existed.
    """
    try:
        expected = addr_of(rpc.call("eth_call", [{"to": token, "data": SEL_LAUNCHER}, "latest"]))
    except Exception:  # noqa: BLE001 - no launcher() to compare against, so nothing to filter by
        return list(candidates)
    if int(expected, 16) == 0:
        return list(candidates)

    kept, dropped = [], []
    for address in candidates:
        try:
            answer = rpc.call("eth_call", [{"to": address, "data": SEL_LAUNCHER}, "latest"])
        except Exception:  # noqa: BLE001 - a revert is the answer: not a launchpad coin
            answer = None
        (kept if answer and len(answer) >= 66 and addr_of(answer) == expected
         else dropped).append(address)
    if dropped:
        log("dropped %d address(es) that a launch was priced against, not coins: %s"
            % (len(dropped), ", ".join(dropped[:4])))
    return kept


def top_child(rpc, token, state, fresh_children, limit, log):
    """Largest market cap among coins the launchpad has produced."""
    known = launchpad_coins(
        rpc, token, sorted(set(state.get("childTokens", [])) | set(fresh_children)), log)
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
                label=esc(entry["label"]), price=num(fmt_usd(entry["price"])),
                low=fmt_usd(entry["low"]), high=fmt_usd(entry["high"]),
                at=round(entry["atPercent"]), down=round(entry["toLow"], 2),
                up=round(entry["toHigh"], 2), stock=round(entry["stockPercent"]),
                symbol=esc(entry["symbol0"]), value=fmt_usd(entry["valueUsd"]),
                fees=fmt_small(entry["feesUsd"]))))
        else:
            side = text["lpBelow"] if entry["price"] <= entry["low"] else text["lpAbove"]
            lines.append(row("down", text["lpLineOut"].format(
                label=esc(entry["label"]), price=num(fmt_usd(entry["price"])), side=side,
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
                label=esc(row["label"]), side=side, price=num(fmt_usd(row["price"])),
                low=fmt_usd(row["low"]), high=fmt_usd(row["high"])))
        elif was_out and not is_out:
            alerts.append(mark(text, "up") + " " + text["lpBack"].format(
                label=esc(row["label"]), price=num(fmt_usd(row["price"])),
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

def fuel_window(now, state, window):
    """Buyback fuel over the last `window` completed days, and the merged history.

    Judged over a window, not a day: the locker is emptied in bursts, so one quiet
    day says nothing while a quiet week says the buyback has nothing left to spend.
    Sets the two figures on `now` so the digest can print them on a first run too,
    before any threshold exists to compare them against.
    """
    history = dict(state.get("fuelByDay", {}))
    history.update(now.get("fuelByDay", {}))
    days = [d for d in sorted(history) if d != day_key(now["measuredAt"])][-window:]
    now["fuelWindow"] = round(sum(history.get(d, 0.0) for d in days), 3)
    now["fuelWindowDays"] = len(days)
    return history, days


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

    window = int(th.get("fuelWindowDays", 5))
    fuel_history, fuel_days = fuel_window(now, state, window)
    if "fuelEthBelow" in th and len(fuel_days) >= window:
        flip("fuelDry", now["fuelWindow"] < th["fuelEthBelow"], text["fuelDry"].format(
            days=window, value=round(now["fuelWindow"], 2), limit=th["fuelEthBelow"],
            detail=", ".join("%s: %.2f" % (d, fuel_history.get(d, 0.0)) for d in fuel_days)))

    return alerts, flags, history, rev_history, fuel_history


# --------------------------------------------------------------- presentation

def esc(value):
    """Telegram parses the message as HTML, and a token symbol is attacker-chosen text."""
    return html.escape(str(value), quote=False)


def bold(value):
    return "<b>" + esc(value) + "</b>"


def num(value):
    """A measured number, set in the monospace face.

    Bold was doing this job and doing it badly: on a line with four figures,
    everything shouted and the eye had nothing to land on. Monospace makes the
    digits line up between lines and reads, in Telegram's dark theme, the way a
    number is supposed to read next to a word."""
    return "<code>" + esc(value) + "</code>"


def mark(text, kind):
    """The marker for a line. Direction is an arrow, trouble is a red circle.

    It used to be a coloured circle in front of every line, and with a dozen lines
    that is a column of decorative dots carrying no information -- his words were
    "just coloured balls". Now the line starts with an icon that says what the line
    is about, and the marker only appears where it means something: which way a
    number moved, or that something needs attention."""
    return text.get("marks", {}).get(kind, "")


# Direction reads better after the number it describes, the way a ticker prints it.
TRAILING_MARKS = ("up", "down", "flat", "info")


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
    out = []
    for line in lines:
        glyph = mark(text, line["kind"])
        if line["kind"] in TRAILING_MARKS:
            out.append(("%s %s" % (line["text"], glyph)).strip())
        else:
            out.append(("%s %s" % (glyph, line["text"])).strip())
    return "\n".join(out)


def fmt_change(change):
    return ("%+.1f%%" % change) if isinstance(change, (int, float)) else "-"


def fmt_age(created_ms):
    """How old the pool is. A coin two days old is a different proposition from one
    that has traded for a year, and the number is never on the chart."""
    if not created_ms:
        return None
    days = (time.time() - float(created_ms) / 1000) / 86400
    if days < 1:
        return "%dч" % max(1, round(days * 24))
    if days < 90:
        return "%dд" % round(days)
    return "%dмес" % round(days / 30)


def coin_card(info, text, held_usd=None):
    """The full picture of one coin, for the moment something about it is worth saying.

    A digest line names a coin; this says whether to act on it. Everything here comes
    from the pair data already fetched for the price, so it costs no extra request:

      price and the three windows -- 1h/6h/24h answers "still going, or rolled over?"
      cap against liquidity     -- the exit test. A $500M coin over a $9M pool is a
                                   different animal from the same cap over $200k, and
                                   the ratio says which without opening a chart.
      buys against sells        -- who is on the other side of the exit
      age                       -- how much history the price actually has
    """
    lines = []
    price = info.get("price") or 0
    # This is the line a person reads in the notification preview, so it carries the
    # four things worth knowing before opening anything: which coin, what it costs,
    # what the whole thing is worth, and which way it is going.
    cap_now = info.get("marketCap") or 0
    head = "%s %s" % (bold(esc(info.get("symbol") or "?")),
                      num(fmt_usd(price)) if price else "-")
    if cap_now:
        head += " " + num("[%s]" % fmt_usd(cap_now))
    head = (head + " " + mark(text, sign_of(info.get("change24")))).strip()
    if held_usd:
        head += "  " + text["cardHeld"].format(usd=fmt_usd(held_usd))
    lines.append(head)

    windows = text["cardWindows"].format(
        h1=fmt_change(info.get("change1")), h6=fmt_change(info.get("change6")),
        h24=fmt_change(info.get("change24")))
    lines.append(windows)

    liq = info.get("liquidityTotal") or info.get("liquidity") or 0
    cap = info.get("marketCap") or 0
    # Cap against pool depth, as a single number: 9 means the whole coin is worth
    # nine times what sits in its pools, and that is the exit test.
    ratio = (" " + num("[×%d]" % round(cap / liq))) if liq and cap else ""
    lines.append(text["cardDepth"].format(cap=fmt_usd(cap) if cap else "-",
                                          liq=fmt_usd(liq) if liq else "-", ratio=ratio,
                                          vol=fmt_usd(info.get("volume24") or 0)))

    buys, sells = info.get("buys24") or 0, info.get("sells24") or 0
    age = fmt_age(info.get("pairCreatedAt"))
    tail = []
    if buys or sells:
        tail.append(text["cardFlow"].format(buys=format(buys, ","), sells=format(sells, ",")))
    if age:
        tail.append(text["cardAge"].format(age=age))
    if info.get("poolCount"):
        tail.append(text["cardPools"].format(n=info["poolCount"]))
    if tail:
        lines.append(" · ".join(tail))
    if info.get("url"):
        lines.append('<a href="%s">%s</a>' % (esc(info["url"]), text["cardChart"]))
    return "\n".join(lines)


def fmt_usd(value):
    """Money, at the precision that band of money is actually read at.

    Six decimals below a dollar was one rule for two different jobs: a coin at $0.72
    came out as "$0.723200", which is noise, while a memecoin at 4.7e-7 came out as
    "$0.000000", which is wrong. Each band now gets the digits it needs.
    """
    value = float(value or 0)
    if value >= 1_000_000_000:
        return "$%.2fB" % (value / 1_000_000_000)
    if value >= 1_000_000:
        return "$%.2fM" % (value / 1_000_000)
    if value >= 1000:
        return "$%s" % format(int(round(value)), ",")
    if value >= 1:
        return "$%.2f" % value
    if value >= 0.01:
        return "$%.4f" % value
    if value >= 0.000001:
        return "$%.6f" % value
    if value > 0:
        # Sub-microdollar coins are real here; rounding them to zero hides a position.
        return "$%.2e" % value
    return "$0.00"


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
            revenue=num(fmt_usd(revenue)))),
        row("info", text["digestBurn"].format(
            burned=format(int(round(now["burned"])), ","),
            burnedPercent=round(now["burnedPercent"], 2))),
        row("info", text["digestChild"].format(
            childSymbol=esc(now.get("topChildSymbol") or "-"),
            child=fmt_usd(now.get("topChildMcap", 0)))),
        row("info", text["digestFuel"].format(
            eth=("%.2f" % now.get("fuelWindow", 0)), days=now.get("fuelWindowDays", 0))),
        row(sign_of(price_change), text["digestMarket"].format(
            price=num(fmt_usd(now["price"])), cap=fmt_usd(now["marketCap"]),
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


OUTBOX_PATH = os.path.join("state", "outbox.jsonl")
OUTBOX_MAX = 200
OUTBOX_MAX_AGE = 3 * 24 * 3600


def outbox_add(message, log):
    """Hold a message the network refused to carry.

    The watcher runs on a laptop, and a laptop loses DNS -- 404 failed lookups in
    one day is what the logs actually show. A send that raises used to end there:
    the alert was composed, written to the log, and thrown away. Now it waits on
    disk instead, and the next run that reaches Telegram carries it.
    """
    entry = {"at": int(time.time()), "text": message}
    try:
        os.makedirs(os.path.dirname(OUTBOX_PATH), exist_ok=True)
        pending = outbox_read()
        pending.append(entry)
        outbox_write(pending[-OUTBOX_MAX:])
        log("telegram: held in the outbox, %d waiting" % len(pending[-OUTBOX_MAX:]))
    except Exception as exc:  # noqa: BLE001 - the outbox must never break a run
        log("telegram: outbox unwritable (%s), message lost" % exc)


def outbox_read():
    if not os.path.exists(OUTBOX_PATH):
        return []
    cutoff = time.time() - OUTBOX_MAX_AGE
    kept = []
    with open(OUTBOX_PATH, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            # A three-day-old alert is history, not news. Dropping it keeps the
            # queue from growing without bound during a long outage.
            if entry.get("at", 0) >= cutoff:
                kept.append(entry)
    return kept


def outbox_write(entries):
    with open(OUTBOX_PATH, "w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def outbox_flush(token, chat_id, log):
    """Deliver what earlier runs could not, oldest first, before anything new."""
    pending = outbox_read()
    if not pending:
        return
    log("telegram: %d message(s) waiting from earlier runs" % len(pending))
    left = []
    for index, entry in enumerate(pending):
        if left:  # the line is down again; stop hammering it
            left.append(entry)
            continue
        stamp = time.strftime("%d.%m %H:%M", time.localtime(entry.get("at", 0)))
        held = "\n\n<i>(отложено %s, доставлено сейчас)</i>" % stamp
        if not telegram(token, chat_id, entry["text"] + held, log, queue=False):
            left.append(entry)
    outbox_write(left)
    delivered = len(pending) - len(left)
    if delivered:
        log("telegram: delivered %d held message(s)" % delivered)
    if left:
        log("telegram: %d still waiting" % len(left))


def telegram(token, chat_id, message, log, queue=True):
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
        # A refusal and an outage are different failures. Telegram saying no to the
        # markup is final; DNS saying nothing is temporary, so only this branch queues.
        log("telegram: failed -- %s" % exc)
        if queue:
            outbox_add(message, log)
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
    elif profile == "revenue":
        now = measure_revenue(cfg, log)
        lines = digest_revenue(now, text)
        alerts, flags = ([], {}) if first_run else evaluate_revenue(cfg, now, state, text)
        state_out = {"baseline": True, "measuredAt": now["measuredAt"],
                     "lastAverage": now["average"], "lastDay": now["latestDay"],
                     "flags": flags}
    elif profile == "lp":
        now = measure_lp(cfg, Rpc(cfg["rpc"]), log)
        lines = digest_lp(now, text)
        alerts, flags = ([], {}) if first_run else evaluate_lp(cfg, now, state, text)
        state_out = {"baseline": True, "measuredAt": now["measuredAt"], "flags": flags}
    elif profile == "wallet":
        now = measure_wallet(cfg, log, state.get("knownTokens"),
                             scanned_to=state.get("scannedToBlock", 0),
                             discovered=state.get("discoveredTokens"))
        log("holdings: %d worth %s, %d spam tokens ignored" % (
            len(now["holdings"]), fmt_usd(now["totalUsd"]), now["spamCount"]))
        lines = digest_wallet(now, text, state.get("totalUsd"))
        alerts, flags = ([], {}) if first_run else evaluate_wallet(cfg, now, state, text)
        state_out = {
            "baseline": True,
            "measuredAt": now["measuredAt"],
            # A run that could not read every balance holds a total that is too low by
            # whatever it missed. Saving it would make the next full run look like a
            # jump, so the last complete figure stays the baseline.
            "totalUsd": (state.get("totalUsd") if now.get("partial") and state.get("totalUsd")
                         else now["totalUsd"]),
            "knownTokens": now["knownTokens"] or state.get("knownTokens") or [],
            "discoveredTokens": now.get("discoveredTokens") or state.get("discoveredTokens") or [],
            "scannedToBlock": now.get("scannedToBlock") or state.get("scannedToBlock", 0),
            "flags": flags,
        }
    else:
        rpc = Rpc(cfg["rpc"])
        # The first run reaches further back so the day history and the list of coins
        # the launchpad produced start out populated instead of empty.
        days_back = cfg["seedDays"] if first_run else cfg["windowDays"]
        now = measure(cfg, rpc, log, days_back)
        cap, symbol, known_children = top_child(
            rpc, cfg["watch"]["token"], state, now["childTokens"],
            cfg["watch"]["childScanLimit"], log)
        now["topChildMcap"] = cap
        now["topChildSymbol"] = symbol

        log("launches: %s" % (", ".join("%s=%d" % kv for kv in sorted(now["launchesByDay"].items())) or "none"))
        log("revenue:  %s" % (", ".join("%s=$%d" % (k, round(v)) for k, v in sorted(now["revenueByDay"].items())) or "none"))
        log("burned:   %s tokens (%.2f%% of supply)" % (format(int(now["burned"]), ","), now["burnedPercent"]))
        log("children: %d known, biggest %s at %s" % (len(known_children), symbol or "-", fmt_usd(cap)))
        log("market:   price %s, cap %s, liquidity %s" % (
            fmt_usd(now["price"]), fmt_usd(now["marketCap"]), fmt_usd(now["liquidity"])))

        fuel_days = int(cfg["thresholds"].get("fuelWindowDays", 5))
        fuel_history, _ = fuel_window(now, state, fuel_days)
        log("fuel:     %.3f ETH out of the locker over %d completed day(s)" % (
            now["fuelWindow"], now["fuelWindowDays"]))

        lines = digest(now, text, state.get("lastPrice"))
        if first_run:
            alerts, flags = [], {}
            history = dict(now["launchesByDay"])
            rev_history = dict(now["revenueByDay"])
        else:
            alerts, flags, history, rev_history, fuel_history = evaluate(cfg, now, state, text)
        state_out = {
            "baseline": True,
            "measuredAt": now["measuredAt"],
            "burnChangedAt": now.get("burnChangedAt"),
            "block": now["block"],
            "burned": now["burned"],
            "flags": flags,
            "launchesByDay": trim_days(history, cfg["keepDays"]),
            "revenueByDay": trim_days(rev_history, cfg["keepDays"]),
            "fuelByDay": trim_days(fuel_history, cfg["keepDays"]),
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
        try:
            print(line)
        except UnicodeEncodeError:
            # A Russian Windows console is cp1251 and cannot render an emoji. The log
            # file is UTF-8 and keeps the real text; only the echo is degraded, and a
            # dry run must not die because the terminal is narrow-minded.
            encoding = getattr(sys.stdout, "encoding", None) or "ascii"
            print(line.encode(encoding, "replace").decode(encoding, "replace"))

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

    # Anything an earlier run could not deliver goes first, and goes even on a run
    # that has nothing new to say -- otherwise a held alert waits for the next change.
    if not args.dry_run and results:
        held_token = os.environ.get(results[0]["notify"]["tokenEnv"], "")
        held_chat = os.environ.get(results[0]["notify"]["chatEnv"], "")
        if held_token and held_chat:
            outbox_flush(held_token, held_chat, log)

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
