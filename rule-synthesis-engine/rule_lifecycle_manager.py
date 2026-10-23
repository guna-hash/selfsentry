"""
rule_lifecycle_manager.py
-----------------------------
Rule Synthesis Engine — Rule Lifecycle Manager.

Tracks ongoing true/false-positive outcomes for deployed auto-generated
rules, writing directly to the real rule_performance table (Phase 8
schema). No backend API route exists for this yet (only
/rules/pending, /approve, /reject, /deprecate), so this module talks
to Postgres directly via psycopg2.

Declared table shape (native PostgreSQL verification is separate):
    rule_performance(id, rule_id -> generated_rules.id,
                      true_positives, false_positives, last_updated)
"""

from __future__ import annotations

import os
from contextlib import closing

import psycopg2
from dotenv import load_dotenv

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_REPO_ROOT, ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL")

RETIREMENT_FP_RATIO_THRESHOLD = 0.5  # if false_positives / total >= this, flag for review


def _get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set (define it in the repository .env)")
    # psycopg2 needs a plain libpq URL, not the SQLAlchemy "+psycopg2" dialect form.
    return psycopg2.connect(DATABASE_URL.replace("+psycopg2", "", 1), connect_timeout=5)


def record_rule_outcome(rule_id: int, was_true_positive: bool) -> None:
    """
    Increments true_positives or false_positives for the given rule_id
    in rule_performance. Creates the row if it doesn't exist yet.
    """
    # Lock the parent rule before checking/inserting. This serializes updates
    # and also protects legacy installations that lack the unique constraint.
    with closing(_get_connection()) as conn, conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM generated_rules WHERE id = %s FOR UPDATE", (rule_id,))
            if cur.fetchone() is None:
                raise LookupError(f"Rule {rule_id} not found")
            cur.execute(
                "SELECT id FROM rule_performance WHERE rule_id = %s ORDER BY id FOR UPDATE",
                (rule_id,),
            )
            rows = cur.fetchall()
            if len(rows) > 1:
                raise RuntimeError("Multiple performance rows for this rule; reconcile data first")
            increments = (int(was_true_positive), int(not was_true_positive))
            if rows:
                cur.execute(
                    """UPDATE rule_performance
                       SET true_positives = COALESCE(true_positives, 0) + %s,
                           false_positives = COALESCE(false_positives, 0) + %s,
                           last_updated = now()
                       WHERE id = %s""",
                    (*increments, rows[0][0]),
                )
            else:
                cur.execute(
                    """INSERT INTO rule_performance
                       (rule_id, true_positives, false_positives, last_updated)
                       VALUES (%s, %s, %s, now())""",
                    (rule_id, *increments),
                )


def evaluate_rule_for_retirement(rule_id: int) -> bool:
    """
    Returns True if this rule's false-positive ratio is high enough to
    flag for human review/retirement (does not auto-deprecate — per
    project design, that decision stays human-gated via the existing
    /rules/{id}/deprecate endpoint).
    """
    with closing(_get_connection()) as conn, conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT true_positives, false_positives FROM rule_performance WHERE rule_id = %s",
                (rule_id,),
            )
            rows = cur.fetchall()

    if len(rows) > 1:
        raise RuntimeError("Multiple performance rows for this rule; reconcile data first")
    if not rows:
        return False  # no data yet — nothing to evaluate

    true_positives, false_positives = rows[0]
    total = (true_positives or 0) + (false_positives or 0)
    if total == 0:
        return False

    fp_ratio = (false_positives or 0) / total
    return fp_ratio >= RETIREMENT_FP_RATIO_THRESHOLD


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SelfSentry - Record a rule outcome or check retirement status"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    record_parser = sub.add_parser("record")
    record_parser.add_argument("rule_id", type=int)
    record_parser.add_argument("outcome", choices=["tp", "fp"])

    check_parser = sub.add_parser("check")
    check_parser.add_argument("rule_id", type=int)

    args = parser.parse_args()

    if args.command == "record":
        record_rule_outcome(args.rule_id, was_true_positive=(args.outcome == "tp"))
        print(f"Recorded {args.outcome} for rule {args.rule_id}")
    elif args.command == "check":
        flagged = evaluate_rule_for_retirement(args.rule_id)
        print(f"Rule {args.rule_id} flagged for retirement review: {flagged}")
