use axum::body::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::error::ApiResult;

/// Corpo JSON tolerante: vazio vira `{}` (o cliente manda POST sem corpo em vários endpoints).
pub fn parse_value(body: &Bytes) -> ApiResult<Value> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(json!({}));
    }
    Ok(serde_json::from_slice(body)?)
}

/// Campo como string; números e booleanos são convertidos, ausente/null vira "".
pub fn s(v: &Value, key: &str) -> String {
    opt_s(v, key).unwrap_or_default()
}

pub fn opt_s(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(x) => Some(x.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn i(v: &Value, key: &str) -> Option<i64> {
    let x = v.get(key)?;
    x.as_i64()
        .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
}

#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub size: i64,
    pub offset: i64,
}

impl Page {
    /// `?current=1&pageSize=100` como o cliente envia.
    pub fn from_query(q: &HashMap<String, String>) -> Self {
        let current = q
            .get("current")
            .and_then(|x| x.parse::<i64>().ok())
            .unwrap_or(1)
            .max(1);
        let size = q
            .get("pageSize")
            .and_then(|x| x.parse::<i64>().ok())
            .unwrap_or(100)
            .clamp(1, 1000);
        Self {
            size,
            offset: (current - 1) * size,
        }
    }
}

pub fn page_json(total: i64, data: Vec<Value>) -> Value {
    json!({ "total": total, "data": data })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cor determinística para tags criadas pelo servidor (o cliente espera ARGB inteiro).
pub fn tag_color(name: &str) -> i64 {
    let h = name
        .bytes()
        .fold(5381u32, |h, b| h.wrapping_mul(33) ^ u32::from(b));
    i64::from(0xFF00_0000u32 | (h & 0x00FF_FFFF))
}
