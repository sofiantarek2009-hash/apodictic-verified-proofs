import json
import urllib.request
from odoo import api, fields, models
from odoo.exceptions import UserError


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    apodictic_proxy_url = fields.Char(
        string="Apodictic Proxy URL",
        config_parameter="apodictic_odoo_guard.proxy_url",
        default="http://127.0.0.1:8070",
        help="Base URL of `apodictic-mcp-verifier wrap-odoo` reverse proxy.",
    )
    apodictic_mode = fields.Selection(
        [("observe", "Shadow Observe (Non-Blocking)"), ("enforce", "Pre-Commit Enforce (Fail-Closed)")],
        string="Firewall Enforcement Mode",
        config_parameter="apodictic_odoo_guard.mode",
        default="observe",
    )
    apodictic_spend_cap_usd = fields.Float(
        string="Autonomous Spend Cap ($)",
        config_parameter="apodictic_odoo_guard.spend_cap_usd",
        default=50000.0,
    )
    apodictic_enforce_bearer_mcp = fields.Boolean(
        string="Block Mutating Calls on Advisory bearer_scope='mcp'",
        config_parameter="apodictic_odoo_guard.enforce_bearer_scope_mcp",
        default=True,
    )
    apodictic_hitl_webhook_url = fields.Char(
        string="CFO HITL Webhook URL (Slack / Teams)",
        config_parameter="apodictic_odoo_guard.hitl_webhook_url",
    )
    apodictic_webhook_secret = fields.Char(
        string="Ingest Webhook HMAC-SHA256 Secret",
        config_parameter="apodictic_odoo_guard.webhook_secret",
    )
    apodictic_last_exposure_summary = fields.Char(
        string="Latest Shadow Exposure Summary",
        config_parameter="apodictic_odoo_guard.last_exposure_summary",
        readonly=True,
    )

    def action_fetch_shadow_exposure(self):
        self.ensure_one()
        base = (self.apodictic_proxy_url or "").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise UserError("Apodictic Proxy URL must start with http:// or https://")

        report_url = f"{base}/_apodictic/report"
        try:
            req = urllib.request.Request(report_url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise UserError(f"Could not reach Apodictic proxy report at {report_url}: {exc}")

        exposure = float(data.get("exposure_usd", 0.0))
        violations = int(data.get("violations_detected", 0))
        observed = int(data.get("observed_would_block", 0))
        blocked = int(data.get("blocked_count", 0))
        summary = (
            f"Violations={violations} (WOULD_BLOCK={observed}, BLOCKED={blocked}) · "
            f"Exposure=${exposure:,.2f}"
        )
        self.env["ir.config_parameter"].sudo().set_param(
            "apodictic_odoo_guard.last_exposure_summary", summary
        )
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Apodictic Proxy Health & Shadow Exposure",
                "message": summary,
                "type": "warning" if violations > 0 else "success",
                "sticky": False,
            },
        }
