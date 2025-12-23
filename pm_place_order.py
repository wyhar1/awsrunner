#!/usr/bin/env python3
import os
import sys
import argparse
import json
import traceback
import time

from py_clob_client.client import ClobClient
from py_clob_client.clob_types import OrderArgs
from py_order_utils.model.signatures import EOA


def load_pk(path: str) -> str:
    if not path:
        env = os.getenv("PM_PK_PATH")
        if not env:
            raise SystemExit("No Polymarket private key provided. Set PM_PK_PATH or pass --pk-path.")
        path = env
    if not os.path.exists(path):
        raise SystemExit(f"Private key file not found: {path}")
    with open(path, "r") as f:
        pk = f.read().strip()
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return pk


def make_client(pk: str) -> ClobClient:
    # Use EOA signature type (matches py_order_utils expectations)
    return ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=pk,
        signature_type=EOA,
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Polymarket CLOB order-placing helper.")
    p.add_argument("--token-id", required=True)
    p.add_argument("--side", required=True, choices=["buy", "sell"])
    p.add_argument("--price", required=True)
    p.add_argument("--size", required=True)
    p.add_argument("--tif", default="GTC", choices=["GTC", "IOC", "FOK"])
    p.add_argument("--pk-path", default="")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main() -> int:
    try:
        args = parse_args()
        pk = load_pk(args.pk_path)
        client = make_client(pk)

        # --- price: accept 0.34 or 34, always convert to 0.01..0.99 ---
        raw_price = float(args.price)
        if raw_price > 1.0:
            price = raw_price / 100.0  # 34 -> 0.34
        else:
            price = raw_price           # 0.34 -> 0.34
        # enforce valid bounds
        if not (0.01 <= price <= 0.99):
            raise ValueError(f"price must be in [0.01, 0.99] (got {price}).")
        # tick rounding
        price = round(price, 2)

        # size
        size = float(args.size)
        if size <= 0:
            raise ValueError(f"size must be > 0 (got {size})")

        # expiration: use seconds epoch (library expects seconds)
        if args.tif == "GTC":
            expiration = 0
        else:
            expiration = int(time.time()) + 30  # 30 seconds from now

        # nonce: microsecond-ish nonzero value
        nonce = int(time.time() * 1_000_000)

        # side must match library enum format
        side = args.side.upper()

        order_args = OrderArgs(
            token_id=args.token_id,
            price=price,
            size=size,
            side=side,
            fee_rate_bps=0,
            nonce=nonce,
            expiration=expiration,
        )

        # Debug: show what we will sign / send
        print("DEBUG OrderArgs:", json.dumps({
            "token_id": order_args.token_id,
            "side": order_args.side,
            "price": order_args.price,
            "size": order_args.size,
            "fee_rate_bps": order_args.fee_rate_bps,
            "nonce": order_args.nonce,
            "expiration": order_args.expiration,
            "taker": getattr(order_args, 'taker', None),
        }, default=str))

        if args.dry_run:
            disp = {
                "token_id": order_args.token_id,
                "side": order_args.side,
                "price": order_args.price,
                "size": order_args.size,
                "tif": args.tif,
                "expiration": order_args.expiration,
            }
            print("DRY RUN. Order args:")
            print(json.dumps(disp, indent=2))
            return 0

        resp = client.create_order(order_args)
        print("Order response:")
        print(json.dumps(resp, indent=2, default=str))
        # treat failed response as error if library returns structure indicating failure
        if isinstance(resp, dict) and not resp.get("success", True):
            print("Order reported failure:", resp)
            return 1
        return 0

    except Exception as e:
        print("Error creating order:")
        print(repr(e))
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
