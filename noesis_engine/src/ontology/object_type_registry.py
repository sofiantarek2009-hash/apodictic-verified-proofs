"""
Apodictic Enterprise Ontology Object Type Registry & Semantic Graph Store.
Defines strongly-typed enterprise financial object schemas (Vendor, Subsidiary,
BankAccount, Contract, Invoice, PurchaseOrder, TaxObligation, Employee, JournalEntry),
temporal validity, property constraints, foreign-link invariants, and cycle detection.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class OntologyDataType(str, Enum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP_MS = "TIMESTAMP_MS"
    CURRENCY_CODE = "CURRENCY_CODE"
    IBAN = "IBAN"
    TAX_ID = "TAX_ID"
    JSON_BLOB = "JSON_BLOB"


@dataclass(frozen=True)
class PropertyDefinition:
    name: str
    data_type: OntologyDataType
    required: bool = True
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    allowed_values: Optional[Tuple[str, ...]] = None
    pii_sensitive: bool = False

    def validate(self, value: Any) -> Optional[str]:
        if value is None:
            if self.required:
                return f"Missing required property '{self.name}'"
            return None

        if self.data_type == OntologyDataType.INTEGER:
            if not isinstance(value, int) or isinstance(value, bool):
                return f"Property '{self.name}' must be INTEGER, got {type(value).__name__}"
            if self.min_value is not None and value < self.min_value:
                return f"Property '{self.name}'={value} < min_value {self.min_value}"
            if self.max_value is not None and value > self.max_value:
                return f"Property '{self.name}'={value} > max_value {self.max_value}"

        elif self.data_type == OntologyDataType.DECIMAL:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return f"Property '{self.name}' must be DECIMAL, got {type(value).__name__}"
            if self.min_value is not None and float(value) < self.min_value:
                return f"Property '{self.name}'={value} < min_value {self.min_value}"
            if self.max_value is not None and float(value) > self.max_value:
                return f"Property '{self.name}'={value} > max_value {self.max_value}"

        elif self.data_type == OntologyDataType.BOOLEAN:
            if not isinstance(value, bool):
                return f"Property '{self.name}' must be BOOLEAN, got {type(value).__name__}"

        elif self.data_type in (
            OntologyDataType.STRING,
            OntologyDataType.CURRENCY_CODE,
            OntologyDataType.IBAN,
            OntologyDataType.TAX_ID,
        ):
            if not isinstance(value, str):
                return f"Property '{self.name}' must be STRING, got {type(value).__name__}"
            if self.data_type == OntologyDataType.CURRENCY_CODE and len(value) != 3:
                return f"Property '{self.name}' must be 3-letter ISO currency code, got '{value}'"
            if self.allowed_values is not None and value not in self.allowed_values:
                return f"Property '{self.name}'='{value}' not in allowed_values {self.allowed_values}"

        elif self.data_type == OntologyDataType.TIMESTAMP_MS:
            if not isinstance(value, int) or value < 0:
                return f"Property '{self.name}' must be non-negative TIMESTAMP_MS"

        return None


@dataclass(frozen=True)
class LinkTypeDefinition:
    link_type: str
    source_object_type: str
    target_object_type: str
    cardinality: str  # "ONE_TO_ONE", "ONE_TO_MANY", "MANY_TO_MANY"
    acyclic_enforced: bool = False
    description: str = ""


@dataclass
class ObjectTypeSchema:
    type_name: str
    primary_key: str
    properties: Dict[str, PropertyDefinition] = field(default_factory=dict)
    description: str = ""

    def validate_instance(self, props: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        if self.primary_key not in props or props[self.primary_key] is None:
            errors.append(f"Missing primary key '{self.primary_key}' for {self.type_name}")
        for prop_name, prop_def in self.properties.items():
            err = prop_def.validate(props.get(prop_name))
            if err:
                errors.append(err)
        return errors


@dataclass
class OntologyObjectInstance:
    object_type: str
    object_id: str
    properties: Dict[str, Any]
    version: int = 1
    valid_from_ms: int = 0
    valid_to_ms: Optional[int] = None
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "object_type": self.object_type,
                "object_id": self.object_id,
                "properties": self.properties,
                "version": self.version,
                "valid_from_ms": self.valid_from_ms,
                "valid_to_ms": self.valid_to_ms,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class OntologyLinkInstance:
    link_id: str
    link_type: str
    source_id: str
    target_id: str
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))


class EnterpriseOntologyRegistry:
    """
    Central semantic graph registry for enterprise financial objects and links.
    Enforces schema validation, referential integrity, and acyclic link constraints.
    """

    def __init__(self, load_standard_financial_ontology: bool = True) -> None:
        self.schemas: Dict[str, ObjectTypeSchema] = {}
        self.link_types: Dict[str, LinkTypeDefinition] = {}
        self.objects: Dict[str, OntologyObjectInstance] = {}
        self.links: Dict[str, OntologyLinkInstance] = {}
        self._outgoing: Dict[str, List[str]] = {}
        self._incoming: Dict[str, List[str]] = {}

        if load_standard_financial_ontology:
            self._register_standard_financial_schemas()

    def _register_standard_financial_schemas(self) -> None:
        self.register_schema(
            ObjectTypeSchema(
                type_name="Subsidiary",
                primary_key="subsidiary_id",
                description="Legal corporate entity within the group consolidation perimeter",
                properties={
                    "subsidiary_id": PropertyDefinition("subsidiary_id", OntologyDataType.STRING),
                    "legal_name": PropertyDefinition("legal_name", OntologyDataType.STRING),
                    "jurisdiction": PropertyDefinition("jurisdiction", OntologyDataType.STRING),
                    "functional_currency": PropertyDefinition("functional_currency", OntologyDataType.CURRENCY_CODE),
                    "cash_balance": PropertyDefinition("cash_balance", OntologyDataType.DECIMAL, min_value=0.0),
                    "min_reserve": PropertyDefinition("min_reserve", OntologyDataType.DECIMAL, min_value=0.0),
                },
            )
        )
        self.register_schema(
            ObjectTypeSchema(
                type_name="Vendor",
                primary_key="vendor_id",
                description="External supplier or contractor",
                properties={
                    "vendor_id": PropertyDefinition("vendor_id", OntologyDataType.STRING),
                    "name": PropertyDefinition("name", OntologyDataType.STRING, pii_sensitive=True),
                    "tax_id": PropertyDefinition("tax_id", OntologyDataType.TAX_ID, pii_sensitive=True),
                    "iban": PropertyDefinition("iban", OntologyDataType.IBAN, required=False, pii_sensitive=True),
                    "risk_score": PropertyDefinition("risk_score", OntologyDataType.DECIMAL, min_value=0.0, max_value=100.0),
                    "created_by_employee_id": PropertyDefinition("created_by_employee_id", OntologyDataType.STRING),
                },
            )
        )
        self.register_schema(
            ObjectTypeSchema(
                type_name="BankAccount",
                primary_key="account_id",
                description="Corporate treasury or operating bank account",
                properties={
                    "account_id": PropertyDefinition("account_id", OntologyDataType.STRING),
                    "iban": PropertyDefinition("iban", OntologyDataType.IBAN, pii_sensitive=True),
                    "currency": PropertyDefinition("currency", OntologyDataType.CURRENCY_CODE),
                    "balance": PropertyDefinition("balance", OntologyDataType.DECIMAL, min_value=0.0),
                    "credit_limit": PropertyDefinition("credit_limit", OntologyDataType.DECIMAL, min_value=0.0),
                },
            )
        )
        self.register_schema(
            ObjectTypeSchema(
                type_name="Invoice",
                primary_key="invoice_id",
                description="Accounts Payable or Receivable invoice",
                properties={
                    "invoice_id": PropertyDefinition("invoice_id", OntologyDataType.STRING),
                    "vendor_id": PropertyDefinition("vendor_id", OntologyDataType.STRING),
                    "currency": PropertyDefinition("currency", OntologyDataType.CURRENCY_CODE),
                    "net_amount": PropertyDefinition("net_amount", OntologyDataType.DECIMAL, min_value=0.0),
                    "vat_amount": PropertyDefinition("vat_amount", OntologyDataType.DECIMAL, min_value=0.0),
                    "status": PropertyDefinition(
                        "status",
                        OntologyDataType.STRING,
                        allowed_values=("DRAFT", "VERIFIED", "APPROVED", "PAID", "REJECTED"),
                    ),
                },
            )
        )
        self.register_schema(
            ObjectTypeSchema(
                type_name="PurchaseOrder",
                primary_key="po_id",
                description="Authorized procurement purchase order",
                properties={
                    "po_id": PropertyDefinition("po_id", OntologyDataType.STRING),
                    "vendor_id": PropertyDefinition("vendor_id", OntologyDataType.STRING),
                    "total_amount": PropertyDefinition("total_amount", OntologyDataType.DECIMAL, min_value=0.0),
                    "currency": PropertyDefinition("currency", OntologyDataType.CURRENCY_CODE),
                },
            )
        )
        self.register_schema(
            ObjectTypeSchema(
                type_name="Employee",
                primary_key="employee_id",
                description="Internal corporate actor with approval authority",
                properties={
                    "employee_id": PropertyDefinition("employee_id", OntologyDataType.STRING),
                    "department": PropertyDefinition("department", OntologyDataType.STRING),
                    "approval_limit": PropertyDefinition("approval_limit", OntologyDataType.DECIMAL, min_value=0.0),
                    "clearance_level": PropertyDefinition("clearance_level", OntologyDataType.INTEGER, min_value=1, max_value=5),
                },
            )
        )

        # Standard Links
        self.register_link_type(LinkTypeDefinition("OWNS_ACCOUNT", "Subsidiary", "BankAccount", "ONE_TO_MANY"))
        self.register_link_type(LinkTypeDefinition("ISSUED_INVOICE", "Vendor", "Invoice", "ONE_TO_MANY"))
        self.register_link_type(LinkTypeDefinition("MATCHES_PO", "Invoice", "PurchaseOrder", "MANY_TO_MANY"))
        self.register_link_type(LinkTypeDefinition("SUBSIDIARY_OF", "Subsidiary", "Subsidiary", "ONE_TO_MANY", acyclic_enforced=True))
        self.register_link_type(LinkTypeDefinition("INTERCOMPANY_FLOW", "Subsidiary", "Subsidiary", "MANY_TO_MANY"))
        self.register_link_type(LinkTypeDefinition("APPROVED_BY", "Invoice", "Employee", "MANY_TO_MANY"))

    def register_schema(self, schema: ObjectTypeSchema) -> None:
        self.schemas[schema.type_name] = schema

    def register_link_type(self, link_def: LinkTypeDefinition) -> None:
        self.link_types[link_def.link_type] = link_def

    def upsert_object(self, object_type: str, object_id: str, properties: Dict[str, Any]) -> OntologyObjectInstance:
        if object_type not in self.schemas:
            raise ValueError(f"Unknown object type '{object_type}'")
        schema = self.schemas[object_type]
        errors = schema.validate_instance(properties)
        if errors:
            raise ValueError(f"Schema validation failed for {object_type}({object_id}): {'; '.join(errors)}")

        existing = self.objects.get(object_id)
        version = existing.version + 1 if existing else 1
        instance = OntologyObjectInstance(
            object_type=object_type,
            object_id=object_id,
            properties=dict(properties),
            version=version,
            valid_from_ms=int(time.time() * 1000),
        )
        self.objects[object_id] = instance
        self._outgoing.setdefault(object_id, [])
        self._incoming.setdefault(object_id, [])
        return instance

    def create_link(
        self,
        link_id: str,
        link_type: str,
        source_id: str,
        target_id: str,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OntologyLinkInstance:
        if link_type not in self.link_types:
            raise ValueError(f"Unknown link type '{link_type}'")
        if source_id not in self.objects:
            raise ValueError(f"Source object '{source_id}' does not exist")
        if target_id not in self.objects:
            raise ValueError(f"Target object '{target_id}' does not exist")

        link_def = self.link_types[link_type]
        src_obj = self.objects[source_id]
        tgt_obj = self.objects[target_id]
        if src_obj.object_type != link_def.source_object_type:
            raise ValueError(f"Link '{link_type}' expects source {link_def.source_object_type}, got {src_obj.object_type}")
        if tgt_obj.object_type != link_def.target_object_type:
            raise ValueError(f"Link '{link_type}' expects target {link_def.target_object_type}, got {tgt_obj.object_type}")

        if link_def.acyclic_enforced and self._would_create_cycle(source_id, target_id, link_type):
            raise ValueError(f"Acyclic constraint violated: adding {link_type}({source_id} -> {target_id}) creates a cycle")

        link = OntologyLinkInstance(
            link_id=link_id,
            link_type=link_type,
            source_id=source_id,
            target_id=target_id,
            weight=weight,
            metadata=metadata or {},
        )
        self.links[link_id] = link
        self._outgoing.setdefault(source_id, []).append(link_id)
        self._incoming.setdefault(target_id, []).append(link_id)
        return link

    def _would_create_cycle(self, source_id: str, target_id: str, link_type: str) -> bool:
        if source_id == target_id:
            return True
        visited: Set[str] = set()
        stack = [target_id]
        while stack:
            curr = stack.pop()
            if curr == source_id:
                return True
            if curr in visited:
                continue
            visited.add(curr)
            for lid in self._outgoing.get(curr, []):
                link = self.links[lid]
                if link.link_type == link_type:
                    stack.append(link.target_id)
        return False

    def get_neighbors(self, object_id: str, link_type: Optional[str] = None) -> List[OntologyObjectInstance]:
        result: List[OntologyObjectInstance] = []
        for lid in self._outgoing.get(object_id, []):
            link = self.links[lid]
            if link_type is None or link.link_type == link_type:
                result.append(self.objects[link.target_id])
        return result

    def detect_cycles(self, link_type: Optional[str] = None) -> List[List[str]]:
        """Tarjan/DFS-based cycle detector for identifying circular wash-trading or VAT carousel fraud."""
        cycles: List[List[str]] = []
        visited: Set[str] = set()
        rec_stack: List[str] = []
        rec_set: Set[str] = set()

        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.append(node)
            rec_set.add(node)

            for lid in self._outgoing.get(node, []):
                link = self.links[lid]
                if link_type is not None and link.link_type != link_type:
                    continue
                nxt = link.target_id
                if nxt not in visited:
                    dfs(nxt)
                elif nxt in rec_set:
                    idx = rec_stack.index(nxt)
                    cycles.append(rec_stack[idx:] + [nxt])

            rec_stack.pop()
            rec_set.remove(node)

        for obj_id in self.objects:
            if obj_id not in visited:
                dfs(obj_id)

        return cycles
