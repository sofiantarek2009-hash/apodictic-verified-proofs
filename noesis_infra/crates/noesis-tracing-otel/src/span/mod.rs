use crate::propagation::{SpanContext, SpanId, TraceFlags, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SpanKind {
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StatusCode {
    Unset,
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStatus {
    pub code: StatusCode,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp_unix_nanos: u64,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanData {
    pub context: SpanContext,
    pub parent_span_id: Option<SpanId>,
    pub name: String,
    pub kind: SpanKind,
    pub start_time_unix_nanos: u64,
    pub end_time_unix_nanos: Option<u64>,
    pub attributes: HashMap<String, String>,
    pub events: Vec<SpanEvent>,
    pub status: SpanStatus,
}

pub struct ActiveSpan {
    pub data: SpanData,
}

impl ActiveSpan {
    pub fn new(name: &str, kind: SpanKind, parent: Option<&SpanContext>) -> Self {
        let (trace_id, parent_span_id) = if let Some(p) = parent {
            (p.trace_id, Some(p.span_id))
        } else {
            (TraceId::new_random(), None)
        };

        let span_id = SpanId::new_random();
        let context = SpanContext {
            trace_id,
            span_id,
            trace_flags: TraceFlags::SAMPLED,
        };

        let now_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            data: SpanData {
                context,
                parent_span_id,
                name: name.to_string(),
                kind,
                start_time_unix_nanos: now_nanos,
                end_time_unix_nanos: None,
                attributes: HashMap::new(),
                events: Vec::new(),
                status: SpanStatus {
                    code: StatusCode::Unset,
                    description: None,
                },
            },
        }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.data.attributes.insert(key.to_string(), value.to_string());
    }

    pub fn add_event(&mut self, name: &str) {
        let now_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        self.data.events.push(SpanEvent {
            name: name.to_string(),
            timestamp_unix_nanos: now_nanos,
            attributes: HashMap::new(),
        });
    }

    pub fn end(mut self) -> SpanData {
        let now_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        self.data.end_time_unix_nanos = Some(now_nanos);
        if self.data.status.code == StatusCode::Unset {
            self.data.status.code = StatusCode::Ok;
        }
        self.data
    }
}
