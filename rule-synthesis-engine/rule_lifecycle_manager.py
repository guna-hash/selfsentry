"""
rule_lifecycle_manager.py
-----------------------------
Rule Synthesis Engine — Rule Lifecycle Manager.

Tracks ongoing true/false-positive outcomes for deployed auto-generated
rules, writing directly to the real rule_performance table (Phase 8
schema). No backend API route exists for this yet (only
/rules/pending, /approve, /reject, /deprecate), so this module talks
to Postgres directly via psycopg2.

Schema (verified against real DB):
    rule_performance(id, rule_id -> generated_rules.id,
                      true_positives, false_positives, last_updated)
"""

from __future__ import annotations

import os

import psycopg2

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://selfsentry:devpass123@localhost:5432/selfsentry_db",
)

RETIREMENT_FP_RATIO_THRESHOLD = 0.5  # if false_positives / total >= this, flag for review


def _get_connection():
    return psycopg2.connect(DATABASE_URL)


def record_rule_outcome(rule_id: int, was_true_positive: bool) -> None:
    """
    Increments true_positives or false_positives for the given rule_id
    in rule_performance. Creates the row if it doesn't exist yet.
    """
    column = "true_positives" if was_true_positive else "false_positives"

    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO rule_performance (rule_id, true_positives, false_positives, last_updated)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (rule_id) DO UPDATE
                SET {col} = rule_performance.{col} + 1, last_updated = now()
                """.format(col=column),
                (rule_id, 1 if was_true_positive else 0, 0 if was_true_positive else 1),
            )
        conn.commit()


def evaluate_rule_for_retirement(rule_id: int) -> bool:
    """
    Returns True if this rule's false-positive ratio is high enough to
    flag for human review/retirement (does not auto-deprecate — per
    project design, that decision stays human-gated via the existing
    /rules/{id}/deprecate endpoint).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT true_positives, false_positives FROM rule_performance WHERE rule_id = %s",
                (rule_id,),
            )
            row = cur.fetchone()

    if row is None:
        return False  # no data yet — nothing to evaluate

    true_positives, false_positives = row
    total = (true_positives or 0) + (false_positives or 0)
    if total == 0:
        return False

    fp_ratio = (false_positives or 0) / total
    return fp_ratio >= RETIREMENT_FP_RATIO_THRESHOLD


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SelfSentry - Record a rule outcome or check retirement status")
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
