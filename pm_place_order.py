#!/usr/bin/env python3
import os
import sys
import argparse
import json
import traceback
from decimal import Decimal

from py_clob_client.client import ClobClient

# Try to import the types from wherever this version of py_clob_client keeps them
OrderArgs = None
Side = None
TimeInForce = None

try:
    from py_clob_client.clob_types import OrderArgs, Side, TimeInForce
except Exception:
    try:
        from py_clob_client.types import OrderArgs, Side, TimeInForce
    except Exception:
        pass


def load_pk(path: str) -> str:
    if not path:
        path = os.getenv("PM_PK_PATH", "")
    if not path:
        raise SystemExit("No Polymarket private key provided. Set PM_PK_PATH or pass --pk-path.")
    if not os.path.exists(path):
        raise SystemExit(f"Private key file not found: {path}")
    with open(path, "r") as f:
        pk = f.read().strip()
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return pk


def make_client(pk: str) -> ClobClient:
    return ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=pk,
        signature_type="eip712",
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Polymarket CLOB order helper.")
    p.add_argument("--token-id", required=True)
    p.add_argument("--side", required=True, choices=["buy", "sell"])
    p.add_argument("--price", required=True, type=str)
    p.add_argument("--size", required=True, type=str)
    p.add_argument("--tif", default="GTC", choices=["GTC", "IOC", "FOK"])
    p.add_argument("--pk-path", default="")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main() -> int:
    try:
        args = parse_args()
        pk = load_pk(args.pk_path)
        client = make_client(pk)

        price = Decimal(args.price)
        size = Decimal(args.size)

        if OrderArgs is None:
            raise RuntimeError(
                "Could not import OrderArgs from py_clob_client. "
                "Run: python3 -c \"import py_clob_client, pkgutil; print([m.name for m in pkgutil.iter_modules(py_clob_client.__path__)])\""
            )

        # Map to enums if they exist; otherwise pass raw strings.
        side_val = Side.BUY if (Side and args.side == "buy") else (Side.SELL if Side else args.side)
        if TimeInForce:
            tif_val = getattr(TimeInForce, args.tif)
        else:
            tif_val = args.tif

        order_args = OrderArgs(
            token_id=args.token_id,
            side=side_val,
            price=price,
            size=size,
            time_in_force=tif_val,
        )

        if args.dry_run:
            print("DRY RUN. OrderArgs:")
            print(repr(order_args))
            return 0

        resp = client.create_order(order_args)
        print(json.dumps(resp, indent=2, default=str))
        return 0

    except Exception as e:
        print("Error creating order:")
        print(repr(e))
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
