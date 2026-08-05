"""
rules.py
-----------
Module 11 support: FastAPI routes for the Rule Review Queue.

STATUS: NOT YET IMPLEMENTED — Phase 8 stub.

Planned endpoints:
    GET  /rules/pending          - list auto-generated rules awaiting human approval
    POST /rules/{id}/approve     - approve a rule -> triggers rule_deployer.py (Phase 6)
    POST /rules/{id}/reject      - reject a rule (with reason, for lifecycle tracking)
    POST /rules/{id}/deprecate   - retire a previously-deployed rule

This is the backend counterpart to frontend-dashboard/src/pages/RuleReviewQueue.jsx.
The mandatory human-approval gate (project design constraint) lives here.
"""
