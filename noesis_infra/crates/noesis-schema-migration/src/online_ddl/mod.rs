use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OnlineDdlPhase {
    CreateGhostTable,
    CreateSyncTriggers,
    BackfillExistingRows { processed: u64, total: u64 },
    CatchUpBinlog,
    AtomicTableSwap,
    DropOldTable,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineDdlPlan {
    pub original_table: String,
    pub ghost_table: String,
    pub alter_statement: String,
    pub chunk_size: u64,
    pub max_lag_millis: u64,
}

pub struct OnlineDdlExecutor {
    plan: OnlineDdlPlan,
    current_phase: OnlineDdlPhase,
}

impl OnlineDdlExecutor {
    pub fn new(plan: OnlineDdlPlan) -> Self {
        Self {
            plan,
            current_phase: OnlineDdlPhase::CreateGhostTable,
        }
    }

    pub fn generate_ghost_table_ddl(&self) -> String {
        format!(
            "CREATE TABLE {} (LIKE {} INCLUDING ALL);",
            self.plan.ghost_table, self.plan.original_table
        )
    }

    pub fn generate_sync_triggers(&self) -> (String, String, String) {
        let insert_trigger = format!(
            "CREATE OR REPLACE TRIGGER {table}_sync_ins AFTER INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION sync_to_{ghost}();",
            table = self.plan.original_table,
            ghost = self.plan.ghost_table
        );
        let update_trigger = format!(
            "CREATE OR REPLACE TRIGGER {table}_sync_upd AFTER UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION sync_to_{ghost}();",
            table = self.plan.original_table,
            ghost = self.plan.ghost_table
        );
        let delete_trigger = format!(
            "CREATE OR REPLACE TRIGGER {table}_sync_del AFTER DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION sync_to_{ghost}();",
            table = self.plan.original_table,
            ghost = self.plan.ghost_table
        );

        (insert_trigger, update_trigger, delete_trigger)
    }

    pub fn generate_chunked_backfill_query(&self, last_pk: u64) -> String {
        format!(
            "INSERT INTO {} SELECT * FROM {} WHERE id > {} ORDER BY id ASC LIMIT {} ON CONFLICT (id) DO NOTHING;",
            self.plan.ghost_table, self.plan.original_table, last_pk, self.plan.chunk_size
        )
    }

    pub fn generate_atomic_rename_ddl(&self) -> String {
        let archive_name = format!("{}_old_archive", self.plan.original_table);
        format!(
            "RENAME TABLE {} TO {}, {} TO {};",
            self.plan.original_table, archive_name, self.plan.ghost_table, self.plan.original_table
        )
    }
}
