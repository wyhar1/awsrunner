#!/usr/bin/env python
import os
import argparse
import json
from decimal import Decimal

from py_clob_client.client import ClobClient


def load_pk(path: str) -> str:
    if not path:
        env = os.getenv("PM_PK_PATH")
        if not env:
            raise SystemExit(
                "No Polymarket private key provided. "
                "Set PM_PK_PATH or pass --pk-path."
            )
        path = env
    if not os.path.exists(path):
        raise SystemExit(f"Private key file not found: {path}")
    with open(path, "r") as f:
        pk = f.read().strip()
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return pk


def make_client(pk: str) -> ClobClient:
    # If you want testnet instead, change host accordingly.
    # NOTE: py_clob_client.Client signature expects key= (not private_key=).
    # Add chain_id=137 (Polygon mainnet) which is typical for Polymarket.
    return ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=pk,
        signature_type="eip712",
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Simple Polymarket CLOB order-placing helper."
    )
    p.add_argument("--token-id", required=True, help="CLOB token_id for the outcome")
    p.add_argument("--side", required=True, choices=["buy", "sell"], help="Order side")
    p.add_argument(
        "--price",
        required=True,
        type=float,
        help="Limit price in decimal probability (e.g. 0.54)",
    )
    p.add_argument(
        "--size",
        required=True,
        type=float,
        help="Size (number of shares/contracts)",
    )
    p.add_argument(
        "--tif",
        default="GTC",
        choices=["GTC", "IOC", "FOK"],
        help="Time-in-force (default GTC)",
    )
    p.add_argument(
        "--pk-path",
        default="",
        help="Path to private key (overrides PM_PK_PATH if given)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the order payload instead of sending it.",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    pk = load_pk(args.pk_path)

    client = make_client(pk)

    price = Decimal(str(args.price))
    size = Decimal(str(args.size))

    # Basic order payload; this shape is accepted by recent py_clob_client versions.
    order = {
        "token_id": args.token_id,
        "side": args.side,           # "buy" or "sell"
        "price": price,              # Decimal
        "size": size,                # Decimal
        "time_in_force": args.tif,   # plain string
    }

    if args.dry_run:
        print("DRY RUN. Order payload:")
        # Decimal isn’t JSON-serializable by default; convert to string
        print(json.dumps(order, indent=2, default=str))
        return

    try:
        resp = client.create_order(order)
        print("Order response:")
        print(json.dumps(resp, indent=2, default=str))
    except Exception as e:
        print("Error creating order:")
        print(repr(e))


if __name__ == "__main__":
    main()
