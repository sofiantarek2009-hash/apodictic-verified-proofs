"""
Apodictic Autonomous Multi-ERP 3-Way Match & Shadow-Ledger Clearing Kernel.
Combines Z3 combinatorial N-to-M Purchase-Order <-> Goods-Receipt <-> Invoice matching
with Subset-Sum bank statement reconciliation.
"""

from noesis_engine.src.erp_clearing.three_way_match_solver import (
    PurchaseOrderLine,
    GoodsReceiptLine,
    VendorInvoiceLine,
    ThreeWayMatchResult,
    ThreeWayMatchZ3Solver,
)
from noesis_engine.src.erp_clearing.shadow_ledger_reconciler import (
    OpenLedgerInvoice,
    BankSettlementWire,
    SubsetSumMatchResult,
    ShadowLedgerReconciler,
)
from noesis_engine.src.erp_clearing.odoo_eta_pipeline import (
    EmbeddedOdoo18JsonRpcNode,
    EtaInvoiceLineSpec,
    EtaSettlementResult,
    OdooEtaExecutionReceipt,
    OdooEtaFormalClearancePipeline,
    OdooEtaInvoiceRequest,
    canonical_eta_serialize,
)

__all__ = [
    "PurchaseOrderLine",
    "GoodsReceiptLine",
    "VendorInvoiceLine",
    "ThreeWayMatchResult",
    "ThreeWayMatchZ3Solver",
    "OpenLedgerInvoice",
    "BankSettlementWire",
    "SubsetSumMatchResult",
    "ShadowLedgerReconciler",
    "EmbeddedOdoo18JsonRpcNode",
    "EtaInvoiceLineSpec",
    "EtaSettlementResult",
    "OdooEtaExecutionReceipt",
    "OdooEtaFormalClearancePipeline",
    "OdooEtaInvoiceRequest",
    "canonical_eta_serialize",
]
