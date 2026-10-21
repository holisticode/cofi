use axum::{Json, extract::State, http::StatusCode, response::IntoResponse, routing::post, Router};
use cofi_block::{Block, Chain};
use cofi_contracts::{Contribution, state_root};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::NodeCommand;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
    id: Value,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: Value, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub cmd_tx: mpsc::Sender<NodeCommand>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(cmd_tx: mpsc::Sender<NodeCommand>) -> Router {
    let state = Arc::new(AppState { cmd_tx });
    Router::new()
        .route("/", post(handle_rpc))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

// ---------------------------------------------------------------------------
// RPC handler
// ---------------------------------------------------------------------------

async fn handle_rpc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    match dispatch(&state, &req.method, req.params).await {
        Ok(result) => {
            let resp = RpcResponse::success(req.id, result);
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(msg) => {
            let resp = RpcResponse::err(req.id, -32000, &msg);
            (StatusCode::OK, Json(resp)).into_response()
        }
    }
}

async fn dispatch(
    state: &AppState,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    match method {
        "submit_contribution" => submit_contribution(&state, params).await,
        "get_chain_info" => get_chain_info(&state, params).await,
        "get_block" => get_block(&state, params).await,
        "get_state" => get_state(&state, params).await,
        _ => Err(format!("unknown method: {method}")),
    }
}

// ---------------------------------------------------------------------------
// RPC method implementations
// ---------------------------------------------------------------------------

async fn submit_contribution(state: &AppState, params: Value) -> Result<Value, String> {
    let contrib: Contribution = serde_json::from_value(params)
        .map_err(|e| format!("invalid params: {e}"))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .cmd_tx
        .send(NodeCommand::SubmitContribution {
            contribution: contrib,
            reply: reply_tx,
        })
        .await
        .map_err(|_| "node shutting down".to_string())?;

    let pending_id = reply_rx.await.map_err(|_| "node shutting down".to_string())?;
    Ok(serde_json::json!({ "pending_id": pending_id }))
}

async fn get_chain_info(state: &AppState, _params: Value) -> Result<Value, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .cmd_tx
        .send(NodeCommand::GetChainInfo { reply: reply_tx })
        .await
        .map_err(|_| "node shutting down".to_string())?;

    let info = reply_rx.await.map_err(|_| "node shutting down".to_string())?;
    Ok(serde_json::to_value(&info).map_err(|e| e.to_string())?)
}

async fn get_block(state: &AppState, params: Value) -> Result<Value, String> {
    let height: u64 = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing 'height' param".to_string())?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .cmd_tx
        .send(NodeCommand::GetBlock { height, reply: reply_tx })
        .await
        .map_err(|_| "node shutting down".to_string())?;

    let block = reply_rx.await.map_err(|_| "node shutting down".to_string())?;
    Ok(serde_json::to_value(&block).map_err(|e| e.to_string())?)
}

async fn get_state(state: &AppState, _params: Value) -> Result<Value, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .cmd_tx
        .send(NodeCommand::GetState { reply: reply_tx })
        .await
        .map_err(|_| "node shutting down".to_string())?;

    let s = reply_rx.await.map_err(|_| "node shutting down".to_string())?;
    Ok(serde_json::to_value(&s).map_err(|e| e.to_string())?)
}
