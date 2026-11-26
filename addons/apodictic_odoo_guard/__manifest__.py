{
    "name": "Apodictic Pre-Commit Guardrails & Odoo 20 Firewall",
    "version": "18.0.3.11.0",
    "category": "Accounting/Security",
    "summary": "Fail-closed Z3 pre-commit guardrails, /json/2/ shadow exposure audit log, and Ed25519 HITL settings for Odoo 18-20 AI agents.",
    "description": """
Apodictic Odoo Partner Module (Odoo 18-20)
==========================================
- Exposes Settings panel for Apodictic wrap-odoo reverse proxy URL, observe/enforce mode, autonomous spend cap, bearer_scope='mcp' advisory guard, and Slack/Teams HITL webhook.
- One-click 'Sync Shadow Exposure' fetches GET <proxy_url>/_apodictic/report directly into Accounting -> Settings.
- Provides immutable apodictic.audit.event log fed via HMAC-SHA256 authenticated /apodictic/ingest_event JSON webhooks.
    """,
    "author": "Apodictic Systems",
    "website": "https://www.apodictic.dev",
    "license": "LGPL-3",
    "depends": ["base", "account"],
    "data": [
        "security/ir.model.access.csv",
        "views/apodictic_audit_log_views.xml",
        "views/res_config_settings_views.xml",
    ],
    "installable": True,
    "application": False,
    "auto_install": False,
}
