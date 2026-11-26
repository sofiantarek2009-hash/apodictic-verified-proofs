import hashlib
import hmac
import json


def verify_apodictic_signature(secret: str, raw_body: bytes, header_sig: str) -> bool:
    """Verify constant-time HMAC-SHA256 `X-Apodictic-Signature: sha256=<hex>` header."""
    if not secret or not header_sig:
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_sig.strip())


try:
    from odoo import fields, http
    from odoo.http import request
except ImportError:  # Allows standalone unit testing of verify_apodictic_signature outside Odoo
    http = None
    request = None
    fields = None


if http is not None:
    class ApodicticGuardController(http.Controller):
        @http.route("/apodictic/ingest_event", type="json", auth="public", methods=["POST"], csrf=False)
        def ingest_event(self, **kwargs):
            raw_body = request.httprequest.get_data() or b"{}"
            secret = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("apodictic_odoo_guard.webhook_secret", "")
            )
            sig = request.httprequest.headers.get("X-Apodictic-Signature", "")
            if not verify_apodictic_signature(secret, raw_body, sig):
                return {"ok": False, "error": "INVALID_APODICTIC_SIGNATURE"}

            payload = json.loads(raw_body.decode("utf-8"))
            data = payload.get("apodictic") if isinstance(payload.get("apodictic"), dict) else payload
            violations = data.get("violations") or []
            if isinstance(violations, list):
                violations_str = ", ".join(str(v) for v in violations)
            else:
                violations_str = str(violations)

            rec = request.env["apodictic.audit.event"].sudo().create(
                {
                    "occurred_at": fields.Datetime.now(),
                    "mode": str(data.get("mode") or "observe"),
                    "verdict": str(data.get("verdict") or "BLOCKED"),
                    "model_name": str(data.get("model") or "account.move"),
                    "method_name": str(data.get("method") or "create"),
                    "exposure_usd": float(data.get("amount") or data.get("exposure_usd") or 0.0),
                    "violations": violations_str,
                    "tx_digest": str(data.get("tx_digest") or ""),
                    "entry_hash": str(data.get("entry_hash") or ""),
                }
            )
            return {"ok": True, "id": rec.id}
