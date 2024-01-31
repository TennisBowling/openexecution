#![allow(non_camel_case_types)]
use std::sync::Arc;
use lru::LruCache;
use ethereum_types::{Address, H256, H64, U256};
use metastruct::metastruct;
use serde::{Deserialize, Serialize};
use ssz_types::{VariableList, typenum::{U1073741824, U1048576}};
use superstruct::superstruct;
use tokio::sync::RwLock;


#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
    pub fn new_invalid(latest_valid_hash: H256, validation_error: String) -> Self {
        Self {
            status: PayloadStatusStatus::Invalid,
            latest_valid_hash: Some(latest_valid_hash),
            validation_error: Some(validation_error),
        }
    }

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


#[superstruct(variants(V1, V2, V3), variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase")))]
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
    pub transactions: VariableList<VariableList<u8, U1073741824>, U1048576>,    // larger one is max bytes per transaction, smaller one is max transactions per payload
    #[superstruct(only(V2, V3))]
    pub withdrawals: Vec<Withdrawal>,
    #[superstruct(only(V3), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[superstruct(only(V3), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields()))]
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
    pub withdrawals_root: H256,
}

impl ExecutionBlockHeader {
    pub fn from_payload(
        payload: &ExecutionPayload,
        rlp_empty_list_root: H256,
        rlp_transactions_root: H256,
        rlp_withdrawals_root: H256,
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
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    pub iat: i64,
}

#[derive(PartialEq, Clone, Copy)]
pub enum SyncingStatus {
    Synced,
    Offline,
    OnlineAndSyncing,
    NodeNotInitialized,
}

#[derive(Debug)]
pub enum ParseError {
    NoId,
    InvalidJson,
    ElError,
    ResultNotFound,
    CouldNotCastToType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EngineMethod {
    engine_newPayloadV1,
    engine_forkchoiceUpdatedV1,
    engine_getPayloadV1,
    engine_exchangeTransitionConfigurationV1,
    engine_exchangeCapabilities,
    engine_newPayloadV2,
    engine_forkchoiceUpdatedV2,
    engine_getPayloadV2,
    engine_getPayloadBodiesByHashV1,
    engine_getPayloadBodiesByRangeV1,
    engine_newPayloadV3,
    engine_forkchoiceUpdatedV3,
    engine_getPayloadV3,
    
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RpcRequest {
    pub method: EngineMethod,
    pub params: serde_json::Value,
    pub id: u64,
    pub jsonrpc: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcResponse {
    pub result: serde_json::Value,
    pub id: u64,
    pub jsonrpc: String,
}

impl RpcResponse {
    pub fn new(result: serde_json::Value, id: u64) -> Self {
        RpcResponse { result: result, id: id, jsonrpc: "2.0".to_string() }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcErrorResponse {
    pub error: serde_json::Value,
    pub id: u64,
    pub jsonrpc: String,
}

impl RpcErrorResponse {
    pub fn new(error: serde_json::Value, id: u64) -> Self {
        RpcErrorResponse { error: error, id: id, jsonrpc: "2.0".to_string() }
    }
}

impl RpcRequest {
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

#[superstruct(variants(V1, V2, V3), variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase")))]
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
    pub should_override_builder: bool
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
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


pub struct State {
    pub auth_node: Arc<AuthNode>,
    pub unauth_node: Arc<Node>,
    pub fcu_cache: RwLock<LruCache<ForkchoiceState, PayloadStatus>>,
    pub new_payload_cache: RwLock<LruCache<H256, PayloadStatus>>,
}