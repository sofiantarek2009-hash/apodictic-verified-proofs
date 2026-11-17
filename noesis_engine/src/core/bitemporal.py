"""
Apodictic Enterprise Bi-Temporal Accounting Relational Storage Core (SQL:2011)
Tracks dual-orthogonal time dimensions:
1. Valid Time: When an economic fact was valid in the real world [valid_start, valid_end)
2. System Time: When the fact was recorded in the database ledger [system_start, system_end)
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import time

@dataclass
class BiTemporalRecord:
    entity_id: str
    data: Dict[str, Any]
    valid_start: int
    valid_end: int  # -1 represents positive infinity
    system_start: int
    system_end: int  # -1 represents current tip / infinity

class BiTemporalLedger:
    def __init__(self, table_name: str):
        self.table_name = table_name
        self.records: List[BiTemporalRecord] = []

    def insert_fact(self, entity_id: str, data: Dict[str, Any], valid_start: int, valid_end: int = -1, system_time: Optional[int] = None) -> BiTemporalRecord:
        now_sys = int(time.time() * 1000) if system_time is None else system_time
        record = BiTemporalRecord(
            entity_id=entity_id,
            data=data,
            valid_start=valid_start,
            valid_end=valid_end,
            system_start=now_sys,
            system_end=-1
        )
        self.records.append(record)
        return record

    def retroactive_restatement(self, entity_id: str, new_data: Dict[str, Any], effective_valid_start: int, effective_valid_end: int = -1, adjustment_system_time: Optional[int] = None) -> BiTemporalRecord:
        now_sys = int(time.time() * 1000) if adjustment_system_time is None else adjustment_system_time
        
        # Close system time for previously open records for this entity
        for rec in self.records:
            if rec.entity_id == entity_id and rec.system_end == -1:
                rec.system_end = now_sys

        new_rec = BiTemporalRecord(
            entity_id=entity_id,
            data=new_data,
            valid_start=effective_valid_start,
            valid_end=effective_valid_end,
            system_start=now_sys,
            system_end=-1
        )
        self.records.append(new_rec)
        return new_rec

    def as_of(self, entity_id: str, valid_time: int, system_time: int) -> Optional[Dict[str, Any]]:
        """Point-in-time time travel query."""
        for rec in reversed(self.records):
            if rec.entity_id != entity_id:
                continue
            
            # Check valid time range
            v_match = (rec.valid_start <= valid_time) and (rec.valid_end == -1 or valid_time < rec.valid_end)
            # Check system time range
            s_match = (rec.system_start <= system_time) and (rec.system_end == -1 or system_time < rec.system_end)

            if v_match and s_match:
                return rec.data
        return None
