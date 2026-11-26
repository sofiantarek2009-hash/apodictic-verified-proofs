from odoo import fields, models


class ApodicticAuditEvent(models.Model):
    _name = "apodictic.audit.event"
    _description = "Apodictic Pre-Commit Firewall & Z3 Audit Event"
    _order = "occurred_at desc, id desc"

    occurred_at = fields.Datetime(string="Timestamp (UTC)", default=fields.Datetime.now, required=True)
    mode = fields.Char(string="Mode", required=True, default="observe")
    verdict = fields.Char(string="Verdict", required=True)
    model_name = fields.Char(string="Odoo Model", required=True)
    method_name = fields.Char(string="RPC / JSON-2 Method", required=True)
    exposure_usd = fields.Float(string="Dollar Exposure ($)", default=0.0)
    violations = fields.Char(string="Violated Invariants")
    tx_digest = fields.Char(string="Transaction SHA-256 Digest")
    entry_hash = fields.Char(string="WORM Chain Hash")
