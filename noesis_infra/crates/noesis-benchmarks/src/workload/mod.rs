use rand::distributions::Distribution;
use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkloadTransactionType {
    NewOrder,
    Payment,
    OrderStatus,
    Delivery,
    StockLevel,
    SolvencyAudit,
}

pub struct WorkloadGenerator {
    warehouse_count: u32,
    zipf_alpha: f64,
}

impl WorkloadGenerator {
    pub fn new(warehouse_count: u32, zipf_alpha: f64) -> Self {
        Self {
            warehouse_count,
            zipf_alpha,
        }
    }

    pub fn next_transaction_type(&self) -> WorkloadTransactionType {
        let mut rng = rand::thread_rng();
        let p: f64 = rng.gen();

        // TPC-C standard mix adjusted with Apodictic Solvency Auditing
        if p < 0.43 {
            WorkloadTransactionType::NewOrder
        } else if p < 0.86 {
            WorkloadTransactionType::Payment
        } else if p < 0.90 {
            WorkloadTransactionType::OrderStatus
        } else if p < 0.94 {
            WorkloadTransactionType::Delivery
        } else if p < 0.98 {
            WorkloadTransactionType::StockLevel
        } else {
            WorkloadTransactionType::SolvencyAudit
        }
    }

    pub fn generate_sql(&self) -> (WorkloadTransactionType, String) {
        let tx_type = self.next_transaction_type();
        let mut rng = rand::thread_rng();
        let w_id = rng.gen_range(1..=self.warehouse_count);
        let c_id = rng.gen_range(1..=3000);
        let amount = rng.gen_range(100..=500000);

        let sql = match tx_type {
            WorkloadTransactionType::NewOrder => {
                format!(
                    "INSERT INTO orders (w_id, c_id, order_date, item_count, total_amount) VALUES ({}, {}, '2026-04-01', 5, {});",
                    w_id, c_id, amount
                )
            }
            WorkloadTransactionType::Payment => {
                format!(
                    "UPDATE account_balances SET balance = balance - {} WHERE warehouse_id = {} AND customer_id = {};",
                    amount, w_id, c_id
                )
            }
            WorkloadTransactionType::OrderStatus => {
                format!(
                    "SELECT order_id, total_amount, order_status FROM orders WHERE customer_id = {} ORDER BY order_id DESC LIMIT 1;",
                    c_id
                )
            }
            WorkloadTransactionType::Delivery => {
                format!(
                    "UPDATE orders SET order_status = 'DELIVERED' WHERE warehouse_id = {} AND order_status = 'PENDING' LIMIT 10;",
                    w_id
                )
            }
            WorkloadTransactionType::StockLevel => {
                format!(
                    "SELECT COUNT(DISTINCT item_id) FROM stock WHERE warehouse_id = {} AND quantity < 15;",
                    w_id
                )
            }
            WorkloadTransactionType::SolvencyAudit => {
                format!(
                    "SELECT SUM(debit) - SUM(credit) FROM journal_entries WHERE entity_id = {};",
                    w_id
                )
            }
        };

        (tx_type, sql)
    }
}
