#![allow(non_camel_case_types)]
use crate::axum::body::Body;
use axum::response::IntoResponse;
use ethereum_types::{Address, Signature, H256, H64, U256};
use metastruct::metastruct;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_repr::{Deserialize_repr, Serialize_repr};
use ssz_types::{
    typenum::{U1048576, U1073741824, U16, U8192},
    VariableList,
};
use std::{fmt::Debug, str::FromStr, sync::Arc};
use strum::EnumString;
use superstruct::superstruct;
use tokio::sync::broadcast;
use tokio::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq, Hash, EnumString)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadStatusStatus {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatus {
    pub status: PayloadStatusStatus,
    pub latest_valid_hash: Option<H256>,
    pub validation_error: Option<String>,
}

impl PayloadStatus {
    pub fn new_syncing() -> Self {
        Self {
            status: PayloadStatusStatus::Syncing,
            latest_valid_hash: None,
            validation_error: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub index: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub amount: u64,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DepositRequest {
    pub pubkey: Vec<u8>,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: Signature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: Vec<u8>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

// TODO: take a look at this. also try to fix the Vec<u8> into a better type for this and Withdrawal + DepositRequests
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: Vec<u8>,
    pub target_pubkey: Vec<u8>,
}

// TODO: consider not using getter(copy) here. Not sure that we need the Result<T, E> instead of Result<&T, E>

#[superstruct(
    variants(V1, V2, V3, V4),
    variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase"))
)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", untagged, deny_unknown_fields)]
pub struct ExecutionPayload {
    #[superstruct(getter(copy))]
    pub parent_hash: H256,
    #[superstruct(getter(copy))]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: H256,
    #[superstruct(getter(copy))]
    pub receipts_root: H256,
    #[serde(with = "serde_utils::hex_vec")]
    pub logs_bloom: Vec<u8>,
    #[superstruct(getter(copy))]
    pub prev_randao: H256,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub extra_data: Vec<u8>,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u256_hex_be")]
    pub base_fee_per_gas: U256,
    #[superstruct(getter(copy))]
    pub block_hash: H256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: VariableList<VariableList<u8, U1073741824>, U1048576>, // larger one is max bytes per transaction, smaller one is max transactions per payload
    #[superstruct(only(V2, V3))]
    pub withdrawals: Vec<Withdrawal>,
    #[superstruct(only(V3), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[superstruct(only(V3), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
    #[superstruct(only(V4))]
    pub deposit_requests: VariableList<DepositRequest, U8192>,
    #[superstruct(only(V4))]
    pub withdrawal_requests: VariableList<WithdrawalRequest, U16>,
    #[superstruct(only(V4))] // TODO: Turn this into a VariableList
    pub consolidation_requests: Vec<ConsolidationRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields_base(exclude(
    withdrawals_root,
    blob_gas_used,
    excess_blob_gas,
    parent_beacon_block_root
)),))]
pub struct ExecutionBlockHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Vec<u8>,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: H64,
    pub base_fee_per_gas: U256,
    pub withdrawals_root: Option<H256>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<H256>,
}

impl ExecutionBlockHeader {
    pub fn from_payload(
        payload: &ExecutionPayload,
        rlp_empty_list_root: H256,
        rlp_transactions_root: H256,
        rlp_withdrawals_root: Option<H256>,
        rlp_blob_gas_used: Option<u64>,
        rlp_excess_blob_gas: Option<u64>,
        rlp_parent_beacon_block_root: Option<H256>,
    ) -> Self {
        // Most of these field mappings are defined in EIP-3675 except for `mixHash`, which is
        // defined in EIP-4399.
        ExecutionBlockHeader {
            parent_hash: payload.parent_hash(),
            ommers_hash: rlp_empty_list_root,
            beneficiary: payload.fee_recipient(),
            state_root: payload.state_root(),
            transactions_root: rlp_transactions_root,
            receipts_root: payload.receipts_root(),
            logs_bloom: payload.logs_bloom().clone(),
            difficulty: U256::zero(),
            number: payload.block_number().into(),
            gas_limit: payload.gas_limit().into(),
            gas_used: payload.gas_used().into(),
            timestamp: payload.timestamp(),
            extra_data: payload.extra_data().clone(),
            mix_hash: payload.prev_randao(),
            nonce: H64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas(),
            withdrawals_root: rlp_withdrawals_root,
            blob_gas_used: rlp_blob_gas_used,
            excess_blob_gas: rlp_excess_blob_gas,
            parent_beacon_block_root: rlp_parent_beacon_block_root,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    pub iat: i64,
}

#[derive(Debug)]
pub enum ParseError {
    //NoId,
    InvalidJson,
    ElError,
    ResultNotFound,
    CouldNotCastToType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, EnumString)]
pub enum EngineMethod {
    engine_newPayloadV1,
    engine_forkchoiceUpdatedV1,
    engine_getPayloadV1,
    engine_exchangeCapabilities,
    engine_exchangeTransitionConfigurationV1,
    engine_newPayloadV2,
    engine_forkchoiceUpdatedV2,
    engine_getPayloadV2,
    engine_getPayloadBodiesByHashV1,
    engine_getPayloadBodiesByRangeV1,
    engine_newPayloadV3,
    engine_forkchoiceUpdatedV3,
    engine_getPayloadV3,
    engine_getClientVersionV1,
    // Prague
    engine_newPayloadV4,
    engine_getPayloadV4,
    engine_getPayloadBodiesByHashV2,
    engine_getPayloadBodiesByRangeV2,
}

#[derive(Debug)]
pub enum MethodSerializeError {
    CouldNotSerialize,
    NotEngineMethod,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcRequestType {
    Single(GeneralRpcRequest),
    Multiple(Vec<GeneralRpcRequest>),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcResponseResult {
    Ok(RpcResponse),
    Err(RpcErrorResponse),
}

impl From<Result<RpcResponse, RpcErrorResponse>> for RpcResponseResult {
    fn from(result: Result<RpcResponse, RpcErrorResponse>) -> Self {
        match result {
            Ok(response) => RpcResponseResult::Ok(response),
            Err(error) => RpcResponseResult::Err(error),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcResponseType {
    Single(RpcResponseResult),
    Multiple(Vec<RpcResponseResult>),
}

impl IntoResponse for RpcResponseType {
    fn into_response(self) -> axum::http::Response<Body> {
        let body = match self {
            RpcResponseType::Single(result) => serde_json::to_string(&result).unwrap(),
            RpcResponseType::Multiple(results) => serde_json::to_string(&results).unwrap(),
        };

        axum::http::Response::new(Body::from(body))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngineRpcRequest {
    pub method: EngineMethod,
    pub params: serde_json::Value,
    pub id: u64,
    pub jsonrpc: String,
}

impl EngineRpcRequest {
    pub fn from_general(general_request: &GeneralRpcRequest) -> Result<Self, MethodSerializeError> {
        if general_request.method.starts_with("engine") {
            let method = match EngineMethod::from_str(&general_request.method) {
                Ok(method) => method,
                Err(e) => {
                    tracing::error!(
                        "Could not serialize method {} to EngineMethod: {}",
                        general_request.method,
                        e
                    );
                    return Err(MethodSerializeError::CouldNotSerialize);
                }
            };

            let params = match general_request.params.clone() {
                Some(params) => params,
                None => {
                    json!(Vec::<bool>::with_capacity(0))
                }
            };

            return Ok(EngineRpcRequest {
                method,
                params,
                id: general_request.id,
                jsonrpc: "2.0".to_string(),
            });
        }

        Err(MethodSerializeError::NotEngineMethod)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GeneralRpcRequest {
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: u64,
    pub jsonrpc: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcResponse {
    pub result: serde_json::Value,
    pub id: u64,
    pub jsonrpc: String,
}

impl RpcResponse {
    pub fn new(result: serde_json::Value, id: u64) -> Self {
        RpcResponse {
            result,
            id,
            jsonrpc: "2.0".to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize_repr, Serialize_repr)]
#[repr(i32)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    ServerError = -32000,
    UnknownPayload = -38001,
    InvalidForkChoiceState = -38002,
    InvalidPayloadAttributes = -38003,
    TooLargeRequest = -38004,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcErrorResponse {
    pub error: JsonError,
    pub id: u64,
    pub jsonrpc: String,
}

impl RpcErrorResponse {
    /*pub fn parse_error_generic(message: String, id: u64) -> Self {
        RpcErrorResponse {
            error: JsonError { code: ErrorCode::ParseError, message: message },
            id,
            jsonrpc: "2.0".to_string(),
        }
    }*/

    pub fn params_parse_error(message: String, id: u64) -> Self {
        RpcErrorResponse {
            error: JsonError {
                code: ErrorCode::InvalidParams,
                message,
            },
            id,
            jsonrpc: "2.0".to_string(),
        }
    }

    pub fn server_error(message: String, id: u64) -> Self {
        RpcErrorResponse {
            error: JsonError {
                code: ErrorCode::ServerError,
                message,
            },
            id,
            jsonrpc: "2.0".to_string(),
        }
    }

    pub fn internal_error(message: String, id: u64) -> Self {
        RpcErrorResponse {
            error: JsonError {
                code: ErrorCode::InternalError,
                message,
            },
            id,
            jsonrpc: "2.0".to_string(),
        }
    }
}

impl EngineRpcRequest {
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

impl GeneralRpcRequest {
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdatedRequest {
    pub fork_choice_state: ForkchoiceState,
    pub payload_attributes: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatus,
    pub payload_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    pub expected_blob_versioned_hashes: Option<Vec<H256>>,
    pub parent_beacon_block_root: Option<H256>,
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase"))
)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", untagged)]
pub struct GetPayloadResponse {
    #[superstruct(only(V1), partial_getter(rename = "execution_payload_v1"))]
    pub execution_payload: ExecutionPayloadV1,
    #[superstruct(only(V2), partial_getter(rename = "execution_payload_v2"))]
    pub execution_payload: ExecutionPayloadV2,
    #[superstruct(only(V3), partial_getter(rename = "execution_payload_v3"))]
    pub execution_payload: ExecutionPayloadV3,
    #[serde(with = "serde_utils::u256_hex_be")]
    #[superstruct(getter(copy))]
    pub block_value: U256,
    #[superstruct(only(V3))]
    pub blobs_bundle: serde_json::Value,
    #[superstruct(only(V3), partial_getter(copy))]
    pub should_override_builder: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceState {
    head_block_hash: H256,
    safe_block_hash: H256,
    finalized_block_hash: H256,
}

#[derive(Clone)]
pub struct Node {
    pub client: reqwest::Client,
    pub url: String,
}

#[derive(Clone)]
pub struct AuthNode {
    pub client: reqwest::Client,
    pub url: String,
    pub jwt_secret: Arc<jsonwebtoken::EncodingKey>,
}

pub struct PayloadCache<K, V> {
    pub lru: Cache<K, V>,
    pub channels: Cache<K, broadcast::Sender<V>>,
}

impl<K, V> PayloadCache<K, V>
where
    K: std::hash::Hash + std::cmp::Eq + Clone + Send + Sync + 'static + Debug,
    V: std::hash::Hash + Send + Sync + Clone + 'static + Debug,
{
    pub fn new() -> Self {
        PayloadCache {
            lru: Cache::builder().max_capacity(64).build(),
            channels: Cache::builder().max_capacity(64).build(),
        }
    }

    pub async fn insert(&self, key: K, value: V) {
        tracing::info!("Inserting for key {:?}", key);

        tokio::join!(self.lru.insert(key.clone(), value.clone()), async move {
            if let Some(sender) = self.channels.remove(&key).await {
                sender.send(value).unwrap();
            }
        });
    }

    pub async fn get(&self, key: &K) -> Option<V> {
        if let Some(value) = self.lru.get(key).await {
            tracing::info!("Got value for key {:?}", key);
            return Some(value);
        }

        tracing::warn!("Waiting for value to be inserted for key {:?}", key);
        let mut receiver = self
            .channels
            .entry(key.clone())
            .or_insert(broadcast::channel(1).0)
            .await
            .into_value()
            .subscribe();

        tokio::time::timeout(Duration::from_millis(7800), receiver.recv())
            .await
            .ok()
            .map(|x| x.ok())?
    }
}

pub struct State {
    pub auth_node: Arc<AuthNode>,
    pub unauth_node: Arc<Node>,
    pub passthrough_newpayload: bool,
    pub fcu_cache: PayloadCache<ForkchoiceState, PayloadStatus>,
    pub new_payload_cache: PayloadCache<H256, PayloadStatus>,
    pub fork_config: ForkConfig,
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct QuantityU64 {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub value: u64,
}

pub enum ForkName {
    Merge,
    Shanghai,
    Cancun,
    Prague,
}

pub struct ForkConfig {
    //  pub MERGE_FORK_EPOCH: Option<u64> = Some(144896);
    pub shanghai_fork_epoch: u64,
    pub cancun_fork_epoch: u64,
    pub prague_fork_epoch: u64,
}

impl ForkConfig {
    pub fn mainnet() -> Self {
        ForkConfig {
            shanghai_fork_epoch: 194048,
            cancun_fork_epoch: 269568,
            prague_fork_epoch: 99999999999999,
        }
    }

    pub fn holesky() -> Self {
        ForkConfig {
            shanghai_fork_epoch: 256,
            cancun_fork_epoch: 29696,
            prague_fork_epoch: 99999999999999,
        }
    }
}
