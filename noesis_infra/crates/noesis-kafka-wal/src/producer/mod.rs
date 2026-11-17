use crate::protocol::{Record, RecordBatch};
use crate::segment::{LogSegment, SegmentError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};

pub struct PartitionLog {
    dir: PathBuf,
    max_segment_size: usize,
    active_segment: LogSegment,
    closed_segments: Vec<LogSegment>,
    next_offset: AtomicI64,
}

impl PartitionLog {
    pub fn open(dir: &Path, max_segment_size: usize) -> Result<Self, SegmentError> {
        std::fs::create_dir_all(dir)?;
        let active = LogSegment::open(dir, 0, max_segment_size)?;
        let next_offset = active.next_offset;

        Ok(Self {
            dir: dir.to_path_buf(),
            max_segment_size,
            active_segment: active,
            closed_segments: Vec::new(),
            next_offset: AtomicI64::new(next_offset),
        })
    }

    pub fn append_record(&mut self, key: Option<Vec<u8>>, value: Vec<u8>) -> Result<i64, SegmentError> {
        let offset = self.next_offset.fetch_add(1, Ordering::SeqCst);
        let record = Record {
            offset,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            key,
            value,
            headers: Vec::new(),
        };

        let batch = RecordBatch::new(offset, 1001, vec![record]);

        match self.active_segment.append(&batch) {
            Ok(_) => Ok(offset),
            Err(SegmentError::SegmentFull) => {
                // Roll new segment
                let new_base = offset;
                let new_seg = LogSegment::open(&self.dir, new_base, self.max_segment_size)?;
                let old_seg = std::mem::replace(&mut self.active_segment, new_seg);
                self.closed_segments.push(old_seg);
                self.active_segment.append(&batch)?;
                Ok(offset)
            }
            Err(e) => Err(e),
        }
    }

    pub fn read(&mut self, offset: i64) -> Result<Option<RecordBatch>, SegmentError> {
        if offset >= self.active_segment.base_offset {
            if let Some(pos) = self.active_segment.lookup_offset(offset) {
                let batch = self.active_segment.read_batch_at(pos)?;
                return Ok(Some(batch));
            }
            return Ok(None);
        }

        for seg in &mut self.closed_segments {
            if offset >= seg.base_offset && offset < seg.next_offset {
                if let Some(pos) = seg.lookup_offset(offset) {
                    let batch = seg.read_batch_at(pos)?;
                    return Ok(Some(batch));
                }
            }
        }

        Ok(None)
    }
}
