use crate::span::SpanData;
use serde_json::json;
use std::sync::Arc;
use parking_lot::Mutex;

pub trait SpanExporter: Send + Sync {
    fn export(&self, spans: Vec<SpanData>) -> Result<(), String>;
}

pub struct InMemoryOtlpExporter {
    exported_spans: Arc<Mutex<Vec<SpanData>>>,
}

impl InMemoryOtlpExporter {
    pub fn new() -> Self {
        Self {
            exported_spans: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn to_otlp_json(&self) -> String {
        let spans = self.exported_spans.lock();
        let resource_spans: Vec<_> = spans.iter().map(|s| {
            json!({
                "traceId": s.context.trace_id.to_string(),
                "spanId": s.context.span_id.to_string(),
                "parentSpanId": s.parent_span_id.map(|p| p.to_string()),
                "name": s.name,
                "kind": format!("{:?}", s.kind),
                "startTimeUnixNano": s.start_time_unix_nanos,
                "endTimeUnixNano": s.end_time_unix_nanos,
                "attributes": s.attributes,
                "status": {
                    "code": format!("{:?}", s.status.code),
                    "description": s.status.description,
                }
            })
        }).collect();

        json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": {
                        "service.name": "noesis-10k-cluster",
                        "service.version": "2026.4.1"
                    }
                },
                "scopeSpans": [{
                    "scope": { "name": "noesis.tracer" },
                    "spans": resource_spans
                }]
            }]
        }).to_string()
    }
}

impl SpanExporter for InMemoryOtlpExporter {
    fn export(&self, mut spans: Vec<SpanData>) -> Result<(), String> {
        let mut guard = self.exported_spans.lock();
        guard.append(&mut spans);
        Ok(())
    }
}
