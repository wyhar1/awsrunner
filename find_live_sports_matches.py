#!/usr/bin/env python3
"""
Polymarket ↔ Kalshi sports H2H matcher using ONLY ticker/slug codes (no titles).

Match rule:
  Kalshi event_ticker suffix S = last segment after '-' (e.g., 'BOSORL').
  Polymarket strict slug codes -> (A, B).
  A match if S == A+B or S == B+A (case-insensitive).
Timing:
  If both sides have timestamps, require |PM_start - Kalshi_strike| <= --tol-hours.

Run:
  python track_pair.py --out live_sports_matches.csv --debug --tol-hours 72
"""

import argparse
import csv
import time
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Iterable

import requests
import pandas as pd

POLY_GAMMA = "https://gamma-api.polymarket.com"
KALSHI_BASE = "https://api.elections.kalshi.com/trade-api/v2"

# Single-game series on Kalshi
KALSHI_GAME_SERIES = {
    "KXNBAGAME","KXNHLGAME","KXNFLGAME","KXNCAAMBGAME","KXNCAAFGAME",
    "KXEPLGAME","KXLALIGAGAME","KXLIGUE1GAME","KXSERIEAGAME",
    "KXEREDIVISIEGAME","KXLIGAPORTUGALGAME","KXBRASILEIROGAME",
    "KXJLEAGUEGAME","KXLIGAMXGAME","KXALEAGUEGAME","KXSUPERLIGGAME",
}

# Regex to identify series tokens (to skip during team extraction)
SERIES_TOKEN_RE = re.compile(r"^KX[A-Z]+GAME$")  # e.g., KXNBAGAME, KXNHLGAME

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso_to_dt(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def fmt_dt(dt: Optional[datetime]) -> str:
    return dt.isoformat() if isinstance(dt, datetime) else ""

def safe_get(url, params=None, headers=None, timeout=25) -> Any:
    r = requests.get(url, params=params or {}, headers=headers or {}, timeout=timeout)
    r.raise_for_status()
    return r.json()

# ---------- Polymarket: discover sports tags ----------
def _pm_get_sport_tag_ids(debug=False) -> set[int]:
    want: set[int] = set()
    try:
        sports = safe_get(f"{POLY_GAMMA}/sports")
        for row in sports or []:
            tags_field = row.get("tags")
            if isinstance(tags_field, str):
                for tok in re.split(r"\s*,\s*", tags_field.strip()):
                    if tok.isdigit():
                        want.add(int(tok))
            elif isinstance(tags_field, list):
                for t in tags_field:
                    try: want.add(int(t))
                    except: pass
    except Exception as e:
        if debug: print("[Polymarket] /sports failed; fallback to /tags:", e)

    if not want:
        # fallback to /tags heuristic
        offset, limit = 0, 500
        while True:
            data = safe_get(f"{POLY_GAMMA}/tags", params={"limit": limit, "offset": offset})
            if not isinstance(data, list) or not data: break
            for t in data:
                label = (t.get("label") or "").lower()
                slug  = (t.get("slug") or "").lower()
                if any(k in f"{label} {slug}" for k in ["sport","sports","ncaa","ncaaf","ncaab","college","cfb","cbb"]):
                    tid = t.get("id")
                    if tid is not None:
                        try: want.add(int(tid))
                        except: pass
            if len(data) < limit: break
            offset += limit
            time.sleep(0.02)

    if debug: print(f"[Polymarket] sports tag IDs found: {len(want)}")
    return want

def _pm_fetch_markets_by_tag(tag_id: int) -> list[dict]:
    out: list[dict] = []
    offset, limit = 0, 500
    while True:
        params = {"limit": limit, "offset": offset, "order": "updatedAt", "ascending": False, "tag_id": tag_id}
        data = safe_get(f"{POLY_GAMMA}/markets", params=params)
        if not isinstance(data, list) or not data: break
        out.extend(data)
        if len(data) < limit: break
        offset += limit
        time.sleep(0.02)
    return out

# ---------- Polymarket: STRICT-ish code extraction from slug ----------
# pattern: ...-TEAM1-TEAM2-YYYY-MM-DD...
DATE_RE = re.compile(r"\b(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")

# Many NCAA slugs have longer tokens (e.g., "northtexas") — allow 2–10 letters.
ALPHA_RE = re.compile(r"^[a-z]{2,10}$")

def pm_codes_from_slug_strict(slug: str) -> Optional[Tuple[str,str]]:
    """
    Prefer two alphabetic tokens immediately before a valid date token.
    e.g., 'ncaaf-bama-lsu-2025-11-09' -> ('BAMA','LSU')
          'ncaaf-northtexas-utsa-2025-11-09' -> ('NORTHTEXAS','UTSA')
    """
    if not slug: return None
    parts = slug.lower().split("-")
    # find the date token index
    for i in range(len(parts)-2):
        maybe_date = "-".join(parts[i:i+3])
        if DATE_RE.fullmatch(maybe_date):
            # need two tokens before the date
            if i-2 < 0: return None
            a, b = parts[i-2], parts[i-1]
            if ALPHA_RE.fullmatch(a) and ALPHA_RE.fullmatch(b) and a != b:
                return tuple(sorted([a.upper(), b.upper()]))
            # fallback: merge adjacent tokens like 'north-texas'
            if i-3 >= 0:
                aa = parts[i-3] + parts[i-2]
                if ALPHA_RE.fullmatch(aa) and ALPHA_RE.fullmatch(b) and aa != b:
                    return tuple(sorted([aa.upper(), b.upper()]))
            if i-1 >= 1:
                bb = parts[i-1] + parts[i]
                if ALPHA_RE.fullmatch(a) and ALPHA_RE.fullmatch(bb) and a != bb:
                    return tuple(sorted([a.upper(), bb.upper()]))
            return None
    return None

def fetch_polymarket_candidates(debug=False, tol_hours: float = 72.0) -> pd.DataFrame:
    tag_ids = _pm_get_sport_tag_ids(debug=debug)
    if debug: print(f"[Polymarket] scanning markets by {len(tag_ids)} sport tags…")

    raw: list[dict] = []
    for tid in sorted(tag_ids):
        raw.extend(_pm_fetch_markets_by_tag(tid))
        time.sleep(0.02)

    keep = []
    now = now_utc()
    tol = pd.Timedelta(hours=tol_hours)

    for m in raw:
        if m.get("closed") or m.get("archived"): continue
        if not m.get("enableOrderBook"): continue
        if m.get("acceptingOrders") is False: continue

        # Parse start & end times
        start_iso = m.get("eventStartTime") or m.get("gameStartTime")
        end_iso   = m.get("endDate") or m.get("endDateIso")
        start_dt  = iso_to_dt(start_iso) if start_iso else None
        end_dt    = iso_to_dt(end_iso)   if end_iso   else None

        # Must be ongoing/soon-ish
        liveish = False
        if start_dt:
            liveish = abs((start_dt - now).total_seconds()) <= tol_hours * 3600
        elif end_dt:
            liveish = end_dt >= now

        if not liveish:
            continue

        slug = (m.get("slug") or "").strip()
        pair = pm_codes_from_slug_strict(slug)
        if not pair:
            continue

        keep.append({
            "pm_market_id": m.get("id"),
            "pm_slug": slug,
            "pm_pair": pair,  # ('BAMA','LSU') unordered
            "pm_question": (m.get("question") or m.get("description") or "").strip(),
            "pm_event_start": start_iso,
            "pm_end": end_iso,
            "pm_best_bid": m.get("bestBid"),
            "pm_best_ask": m.get("bestAsk"),
            "pm_token_ids": m.get("clobTokenIds"),
        })

    df = pd.DataFrame(keep)
    if debug:
        print(f"[Polymarket] kept STRICT H2H: {len(df)}")
        if not df.empty:
            print(df.head(min(8, len(df)))[["pm_slug","pm_pair"]])
    return df

# ---------- Kalshi helpers: extract pair codes from any ticker ----------
_LAST_SEG_ALPHA = re.compile(r"^[A-Z]{2,6}$")
_CONCAT_SEG_RE  = re.compile(r"^[A-Z]{4,12}$")  # e.g., BOSORL, MILDAL, WPGANA
_MARKET_KIND_TOKENS = {"ML","MONEYLINE","TOTAL","OU","O","U","SPREAD","ATS","HCP","HANDICAP"}

def _last_segment_team_code(mkt_ticker: str) -> Optional[str]:
    if not mkt_ticker:
        return None
    seg = mkt_ticker.split("-")[-1].upper()
    return seg if _LAST_SEG_ALPHA.fullmatch(seg) else None

def _candidate_pairs_from_concat(seg: str) -> Iterable[Tuple[str,str]]:
    """
    Split a concatenated team-code segment (e.g., 'MILDAL') into (A,B) candidates.
    Allow 2..6 letters per side; enumerate all splits.
    """
    seg = seg.upper()
    n = len(seg)
    if not _CONCAT_SEG_RE.fullmatch(seg):
        return []
    out = []
    for i in range(2, n-1):  # split point
        a, b = seg[:i], seg[i:]
        if 2 <= len(a) <= 6 and 2 <= len(b) <= 6:
            out.append(tuple(sorted((a, b))))
    # de-dup while preserving order
    seen = set()
    uniq = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

def _kalshi_pairs_from_ticker(mkt_ticker: str) -> Tuple[set[Tuple[str,str]], set[str]]:
    """
    Return:
      - set of unordered pair candidates inferred from any concatenated segment
      - set of single team codes inferred from moneyline-like last segments
    """
    pairs: set[Tuple[str,str]] = set()
    singles: set[str] = set()

    if not mkt_ticker:
        return pairs, singles

    toks = [t.upper() for t in mkt_ticker.split("-") if t]
    # 1) Moneyline-style last segment
    last = toks[-1] if toks else ""
    if _LAST_SEG_ALPHA.fullmatch(last):
        singles.add(last)

    # 2) Look for concatenated pair segment (often just before market kind)
    for t in toks:
        # NEW: skip series tokens like KXNBAGAME/KXNHLGAME
        if SERIES_TOKEN_RE.fullmatch(t):
            continue
        if t in _MARKET_KIND_TOKENS:
            continue
        # Skip series code / date-ish / with digits/underscores
        if not t.isalpha():
            continue
        if _CONCAT_SEG_RE.fullmatch(t):
            for p in _candidate_pairs_from_concat(t):
                pairs.add(p)
    return pairs, singles

def kalshi_suffix_from_event_ticker(et: str) -> Optional[str]:
    if not et or "-" not in et: return None
    suf = et.split("-")[-1].upper()
    if not re.fullmatch(r"[A-Z]{4,12}", suf):
        return None
    return suf

def _kalshi_series_sports(debug=False) -> list[str]:
    data = safe_get(f"{KALSHI_BASE}/series", params={"category": "Sports"})
    series = data.get("series", []) if isinstance(data, dict) else []
    tickers = [s.get("ticker") for s in series if s.get("ticker")]
    game_series = [t for t in tickers if t in KALSHI_GAME_SERIES]
    if debug:
        print(f"[Kalshi] sports series total: {len(tickers)} | single-game filtered: {len(game_series)}")
    return game_series

def _kalshi_markets_for_series(series_ticker: str, statuses: str, min_close_ts: int) -> list[dict]:
    out, cursor = [], None
    while True:
        params = {
            "series_ticker": series_ticker,
            "status": statuses,            # "open,unopened"
            "min_close_ts": min_close_ts,  # still open or future
            "limit": 1000,
            "mve_filter": "exclude",       # exclude multivariate
        }
        if cursor:
            params["cursor"] = cursor
        data = safe_get(f"{KALSHI_BASE}/markets", params=params)
        mkts = data.get("markets", []) if isinstance(data, dict) else []
        out.extend(mkts)
        cursor = data.get("cursor")
        if not cursor:
            break
        time.sleep(0.02)
    return out

def fetch_kalshi_event_pairs_from_markets(debug=False) -> list[dict]:
    """
    For each single-game event:
      - collect ALL markets (binary/categorical)
      - derive team codes from:
         (a) concatenated pair segments anywhere in the ticker (TOTAL/OU/SPREAD safe),
         (b) moneyline last-segment single codes,
      - if we have any pair candidates, use one; else form a pair from two singles,
      - hydrate strike_date once per event.
    """
    series = _kalshi_series_sports(debug=debug)
    if not series:
        return []

    now_ts = int(now_utc().timestamp())
    statuses = "open,unopened"

    # fetch all relevant markets across series
    mkts: list[dict] = []
    for ser in series:
        m = _kalshi_markets_for_series(ser, statuses=statuses, min_close_ts=now_ts)
        if debug:
            print(f"[Kalshi] {ser}: markets fetched {len(m)}")
        mkts.extend(m)
        time.sleep(0.01)

    # group markets by event
    ev_to_markets: dict[str, list[dict]] = {}
    for m in mkts:
        et = m.get("event_ticker")
        if not et:
            continue
        # keep sports-y markets only (binary or categorical)
        if m.get("market_type") not in {"binary", "categorical"}:
            continue
        ev_to_markets.setdefault(et, []).append(m)

    if debug:
        print(f"[Kalshi] unique event tickers (GAME markets): {len(ev_to_markets)}")

    # hydrate event metadata (strike_date) once per event
    strike_map: dict[str, Optional[datetime]] = {}
    for i, et in enumerate(ev_to_markets.keys()):
        try:
            ev = safe_get(f"{KALSHI_BASE}/events/{et}")
            e = ev.get("event", ev) if isinstance(ev, dict) else {}
            strike_map[et] = iso_to_dt(e.get("strike_date"))
        except Exception:
            strike_map[et] = None
        if i % 20 == 19:
            time.sleep(0.05)

    out: list[dict] = []
    for et, markets in ev_to_markets.items():
        pair_candidates: set[Tuple[str,str]] = set()
        singles: set[str] = set()
        rep_market_ticker: Optional[str] = None

        # NEW: take pairs directly from event_ticker suffix first
        suf = kalshi_suffix_from_event_ticker(et)
        if suf:
            for p in _candidate_pairs_from_concat(suf):
                pair_candidates.add(p)

        # Then scan all market tickers for extra hints
        for m in markets:
            ticker = m.get("ticker") or ""
            ps, ss = _kalshi_pairs_from_ticker(ticker)
            pair_candidates |= ps
            singles |= ss
            # be less picky picking a representative ticker
            if not rep_market_ticker and ticker:
                rep_market_ticker = ticker

        # Resolve a pair deterministically
        pair: Optional[Tuple[str,str]] = None
        if pair_candidates:
            pair = tuple(sorted(next(iter(pair_candidates))))
        elif len(singles) >= 2:
            a, b = sorted(list(singles))[:2]
            pair = (a, b)

        # Last-resort (should rarely trigger now)
        if not pair and suf:
            cps = list(_candidate_pairs_from_concat(suf))
            if cps:
                pair = tuple(sorted(cps[0]))

        if not pair:
            continue

        out.append({
            "kalshi_event_ticker": et,
            "kalshi_market_ticker": rep_market_ticker,
            "kalshi_pair_codes": pair,
            "kalshi_strike": strike_map.get(et)
        })

    if debug:
        print(f"[Kalshi] game events w/ pair codes from tickers: {len(out)}")
        if out:
            print("[Kalshi] sample:", out[0])
    return out

# ---------- Kalshi market ticker derivation from PM slug ----------
def _pts_to_kx_num(s: str) -> Optional[str]:
    """
    Convert PM points notation to Kalshi format:
    "231pt5" -> "231_5", "112pt5" -> "112_5", "3pt5" -> "3_5", "46" -> "46"
    """
    m = re.search(r"(\d+)pt5", s)
    if m:
        return f"{m.group(1)}_5"
    m = re.search(r"(\d+)", s)
    if m:
        return m.group(1)
    return None

def kx_market_for_pm_slug(kx_event_ticker: str, pm_slug: str, pair: Tuple[str,str]) -> Optional[str]:
    """
    Derive the specific Kalshi market ticker from:
      - Kalshi event ticker (e.g., KXNBAGAME-25NOV10MILDAL)
      - Polymarket slug (e.g., nba-mil-dal-2025-11-11-total-231pt5)
      - Team pair codes (('DAL','MIL'))

    Returns market ticker like:
      - KXNBAGAME-25NOV10MILDAL-TOTAL-O231_5
      - KXNBAGAME-25NOV10MILDAL-SPREAD-MIL-2_5
      - KXNBAGAME-25NOV10MILDAL-1H-TOTAL-O112_5
    """
    if not kx_event_ticker or not pm_slug:
        return None

    s = pm_slug.lower()

    # Check for 1H/first half
    half = "-1H" if ("1h-" in s or s.startswith("1h-")) else ""

    # Handle totals
    if "-total-" in s:
        parts = s.split("-total-")
        if len(parts) < 2:
            return None
        val = _pts_to_kx_num(parts[1])
        if not val:
            return None
        # Default to Over; could emit both O and U if needed
        return f"{kx_event_ticker}{half}-TOTAL-O{val}"

    # Handle spreads
    if "-spread-away-" in s or "-spread-home-" in s:
        is_away = "-spread-away-" in s
        parts = s.split("-spread-away-" if is_away else "-spread-home-")
        if len(parts) < 2:
            return None
        val = _pts_to_kx_num(parts[1])
        if not val:
            return None

        # Determine which team is away/home
        # pair is sorted alphabetically, need to preserve actual order from slug
        # Extract teams from slug pattern: sport-team1-team2-date-...
        slug_parts = pm_slug.lower().split("-")
        # Find two consecutive alpha tokens before date
        team_toks = []
        for i, tok in enumerate(slug_parts):
            if ALPHA_RE.fullmatch(tok) and i+1 < len(slug_parts) and ALPHA_RE.fullmatch(slug_parts[i+1]):
                team_toks = [tok.upper(), slug_parts[i+1].upper()]
                break

        if len(team_toks) == 2:
            away_team, home_team = team_toks[0], team_toks[1]
            side = away_team if is_away else home_team
        else:
            # Fallback: use first/second from sorted pair
            side = pair[0] if is_away else pair[1]

        return f"{kx_event_ticker}{half}-SPREAD-{side}-{val}"

    # Moneyline: return None to let C++ watcher pick default
    if "-moneyline" in s or s.endswith("-ml"):
        return None

    # Unknown market type
    return None

# ---------- Matching by unordered pair equality ----------
def match_by_pairs(pm_df: pd.DataFrame, kalshi_rows: List[Dict], tol_hours=72, debug=False) -> List[Dict]:
    """
    Join by unordered team codes:
      - PM: ('A','B') from strict slug → key = frozenset({'A','B'})
      - Kalshi: ('A','B') (from any market ticker pattern) → key = frozenset({'A','B'})
    Time filter applied when both timestamps exist.
    """
    # PM index: frozenset({'A','B'}) -> rows
    pm_ix: Dict[frozenset, List[Dict]] = {}
    for _, r in pm_df.iterrows():
        pair = r.get("pm_pair")
        if not pair or len(pair) != 2:
            continue
        a, b = pair
        key = frozenset({a.upper(), b.upper()})
        pm_ix.setdefault(key, []).append({
            "pm_market_id": r.get("pm_market_id"),
            "pm_slug": r.get("pm_slug"),
            "pm_best_bid": r.get("pm_best_bid"),
            "pm_best_ask": r.get("pm_best_ask"),
            "pm_question": r.get("pm_question"),
            "pm_token_ids": r.get("pm_token_ids") or {},
            "pm_start": iso_to_dt(r.get("pm_event_start")) or iso_to_dt(r.get("pm_end")),
        })

    if debug:
        print(f"[Index] PM pair keys: {len(pm_ix)}")

    matches: List[Dict] = []
    for k in kalshi_rows:
        kp = k.get("kalshi_pair_codes")
        if not kp or len(kp) != 2:
            continue
        ka, kb = kp
        kkey = frozenset({(ka or "").upper(), (kb or "").upper()})
        cands = pm_ix.get(kkey, [])
        if not cands:
            continue

        for p in cands:
            # time proximity (if both)
            kt = k.get("kalshi_strike")
            pt = p.get("pm_start")
            close_enough = True
            if isinstance(kt, datetime) and isinstance(pt, datetime):
                close_enough = abs((pt - kt).total_seconds()) <= tol_hours * 3600
            if not close_enough:
                continue

            token_ids = p["pm_token_ids"]
            yes_id = token_ids.get("yes") if isinstance(token_ids, dict) else None
            no_id  = token_ids.get("no")  if isinstance(token_ids, dict) else None

            teams_codes_concat = "".join(sorted(list(kkey)))

            # Derive specific Kalshi market ticker from PM slug
            kx_event = k.get("kalshi_event_ticker")
            pm_slug = p["pm_slug"]
            derived_mkt = kx_market_for_pm_slug(kx_event, pm_slug, kp)

            # Use derived market ticker if available, else fall back to default
            final_kx_mkt = derived_mkt or k.get("kalshi_market_ticker") or ""

            matches.append({
                "teams_codes_concat": teams_codes_concat,
                "pm_market_id": p["pm_market_id"],
                "pm_slug": p["pm_slug"],
                "pm_yes_token": yes_id,
                "pm_no_token": no_id,
                "pm_best_bid": p["pm_best_bid"],
                "pm_best_ask": p["pm_best_ask"],
                "pm_question": p["pm_question"],
                "pm_event_start_utc": fmt_dt(pt),
                "kalshi_event_ticker": kx_event,
                "kalshi_market_ticker": final_kx_mkt,
                "kalshi_strike_utc": fmt_dt(kt),
            })

    if debug:
        print(f"[Match] total matches: {len(matches)}")
    return matches


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Match Polymarket ↔ Kalshi games by ticker/slug codes only.")
    ap.add_argument("--out", default="live_sports_matches.csv")
    ap.add_argument("--tol-hours", type=float, default=72)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if args.debug:
        print("[Polymarket] fetching Sports + NCAA via tags…")
    pm_df = fetch_polymarket_candidates(debug=args.debug, tol_hours=args.tol_hours)

    if args.debug and not pm_df.empty:
        ncaaf_like = pm_df[pm_df["pm_slug"].str.contains(r"ncaaf|cfb|football", case=False, na=False)]
        print(f"[Debug] NCAAF-ish PM rows: {len(ncaaf_like)}")
        if not ncaaf_like.empty:
            print(ncaaf_like.head(10)[["pm_slug","pm_pair","pm_event_start"]].to_string(index=False))
        print("[Debug] PM samples:", pm_df.head(10)[["pm_slug","pm_pair"]].to_dict("records"))

    if args.debug:
        print("[Kalshi] fetching open/unopened single-game markets…")
    kalshi_rows = fetch_kalshi_event_pairs_from_markets(debug=args.debug)

    if args.debug and kalshi_rows:
        print("[Debug] Kalshi samples:", kalshi_rows[:5])

    if args.debug:
        print("[Match] joining by unordered pair codes…")
    rows = match_by_pairs(pm_df, kalshi_rows, tol_hours=args.tol_hours, debug=args.debug)

    fields = [
        "teams_codes_concat",
        "pm_market_id","pm_slug","pm_yes_token","pm_no_token","pm_best_bid","pm_best_ask",
        "pm_question","pm_event_start_utc",
        "kalshi_event_ticker","kalshi_market_ticker","kalshi_strike_utc",
    ]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print(f"✅ Wrote {len(rows)} matches to {args.out}")

if __name__ == "__main__":
    main()
