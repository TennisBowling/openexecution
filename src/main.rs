mod keccak;
mod types;
mod verify_hash;
use axum::{self, extract::DefaultBodyLimit, Router};
use axum::{extract, Extension};
use axum_extra::TypedHeader;
use ethereum_types::H256;
use headers::authorization::Bearer;
use headers::Authorization;
use lru::LruCache;
use serde_json::json;
use std::any::type_name;
use std::error::Error;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use types::*;
use verify_hash::*;
use tracing_subscriber::filter::EnvFilter;

//  const MERGE_FORK_EPOCH: Option<u64> = Some(144896);
const SHANGHAI_FORK_EPOCH: Option<u64> = Some(194048);
const CANCUN_FORK_EPOCH: Option<u64> = None;
const VERSION: &str = "0.0.1";

fn make_jwt(jwt_secret: &Arc<jsonwebtoken::EncodingKey>, timestamp: &i64) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &Claims {
            iat: timestamp.to_owned(),
        },
        jwt_secret,
    )
    .unwrap()
}

pub fn fork_name_at_epoch(epoch: u64) -> ForkName {
    if let Some(fork_epoch) = CANCUN_FORK_EPOCH {
        if epoch >= fork_epoch {
            return ForkName::Cancun;
        }
    }
    if let Some(fork_epoch) = SHANGHAI_FORK_EPOCH {
        if epoch >= fork_epoch {
            return ForkName::Shanghai;
        }
    }
    ForkName::Merge
}

fn timestamp_to_version(timestamp: &u64) -> Option<ForkName> {
    // 32 slots/epoch
    let slot = timestamp.checked_sub(1606824000)?.checked_div(12)?;     // genesis time / seconds per slot
    let epoch = slot.checked_div(32)?;      // slot / slots per epoch
    Some(fork_name_at_epoch(epoch))
}

fn new_payload_serializer(
    mut request: EngineRpcRequest,
) -> Result<NewPayloadRequest, RpcErrorResponse> {
    let params = match request.params.as_array_mut() {
        Some(params_vec) => params_vec,
        None => {
            tracing::error!("Could not serialize newPayload's params into a vec.");
            return Err(RpcErrorResponse::new(
                json!("Could not serialize newPayload's params into a vec."),
                request.id,
            ));
        }
    };

    if request.method == EngineMethod::engine_newPayloadV3 {
        // params will have 3 fields: [ExecutionPayloadV3, expectedBlobVersionedHashes, ParentBeaconBlockRoot]
        if params.len() != 3 {
            tracing::error!("newPayloadV3's params did not have 3 elements.");
            return Err(RpcErrorResponse::new(
                json!("newPayloadV3's params did not have 3 elements."),
                request.id,
            ));
        }

        let execution_payload: ExecutionPayloadV3 = match serde_json::from_value(params[0].take()) {
            // direct getting is safe here since we checked that we have least 3 elements
            Ok(execution_payload) => execution_payload,
            Err(e) => {
                tracing::error!(
                    "Could not serialize ExecutionPayload from newPayloadV3: {}",
                    e
                );
                return Err(RpcErrorResponse::new(
                    json!("Could not serialize ExecutionPayload."),
                    request.id,
                ));
            }
        };

        let versioned_hashes: Vec<H256> = match serde_json::from_value(params[1].take()) {
            Ok(versioned_hashes) => versioned_hashes,
            Err(e) => {
                tracing::error!(
                    "Could not serialize VersionedHashes from newPayloadV3: {}",
                    e
                );
                return Err(RpcErrorResponse::new(
                    json!("Could not serialize Versioned Hashes."),
                    request.id,
                ));
            }
        };

        let parent_beacon_block_root: H256 = match serde_json::from_value(params[2].take()) {
            Ok(parent_beacon_block_root) => parent_beacon_block_root,
            Err(e) => {
                tracing::error!(
                    "Could not serialize ParentBeaconBlockRoot from newPayloadV3: {}",
                    e
                );
                return Err(RpcErrorResponse::new(
                    json!("Could not serialize ParentBeaconBlockRoot."),
                    request.id,
                ));
            }
        };

        return Ok(NewPayloadRequest {
            execution_payload: types::ExecutionPayload::V3(execution_payload),
            expected_blob_versioned_hashes: Some(versioned_hashes),
            parent_beacon_block_root: Some(parent_beacon_block_root),
        });
    }

    // parmas will just have [ExecutionPayloadV1 | ExecutionPayloadV2]

    if params.len() != 1 {
        tracing::error!("newPayloadV1|2's params did not have anything or something went wrong (newPayloadV1|2 called with more than just 1 param (ExecutionPayload).");
        return Err(RpcErrorResponse::new(
            json!("newPayloadV1|2's params did not have anything."),
            request.id,
        ));
    }

    let QuantityU64 {value: timestamp } = match params[0].get("timestamp") {
        Some(timestamp) => {
            match serde_json::from_value(timestamp.clone()) {
                Ok(timestamp) => timestamp,
                Err(e) => {
                    tracing::error!("Execution payload timestamp is not representable as u64: {}. Timestamp: {}", e, timestamp);
                    return Err(RpcErrorResponse::new(json!("Execution payload timestamp is not representable as u64"), request.id));
                }
            }
        },
        None => {
            tracing::error!("Execution payload does not have timestamp");
            return Err(RpcErrorResponse::new(json!("Execution payload does not have timestamp"), request.id));
        }
    };

    let fork_name = match timestamp_to_version(&timestamp) {
        Some(fork_name) => fork_name,
        None => {
            tracing::error!("Error converting execution payload timestamp to fork name");
            return Err(RpcErrorResponse::new(json!("Error converting execution payload timestamp to fork name"), request.id));
        }
    };

    let execution_payload = match fork_name {
        ForkName::Merge => {
            match serde_json::from_value::<ExecutionPayloadV1>(params[0].take()) {
                Ok(execution_payload) => ExecutionPayload::V1(execution_payload),
                Err(e) => {
                    tracing::error!(
                        "Could not serialize ExecutionPayloadV1 from newPayloadV1|2; Merge fork. Error: {}",
                        e
                    );
                    return Err(RpcErrorResponse::new(
                        json!("Could not serialize ExecutionPayload."),
                        request.id,
                    ));
                }
            }
        },
        ForkName::Shanghai => {
            match serde_json::from_value::<ExecutionPayloadV2>(params[0].take()) {
                Ok(execution_payload) => ExecutionPayload::V2(execution_payload),
                Err(e) => {
                    tracing::error!(
                        "Could not serialize ExecutionPayloadV2 from newPayloadV2; Shanghai fork. Error: {}",
                        e
                    );
                    return Err(RpcErrorResponse::new(
                        json!("Could not serialize ExecutionPayload."),
                        request.id,
                    ));
                }
            }
        },
        ForkName::Cancun => {
            match serde_json::from_value::<ExecutionPayloadV3>(params[0].take()) {
                Ok(execution_payload) => ExecutionPayload::V3(execution_payload),
                Err(e) => {
                    tracing::error!(
                        "Could not serialize ExecutionPayloadV3 from newPayloadV3; Cancun fork. Error: {}",
                        e
                    );
                    return Err(RpcErrorResponse::new(
                        json!("Could not serialize ExecutionPayload."),
                        request.id,
                    ));
                }
            }
        },
    };


    Ok(NewPayloadRequest {
        execution_payload,
        expected_blob_versioned_hashes: None,
        parent_beacon_block_root: None,
    })
}

fn fcu_serializer(
    mut request: EngineRpcRequest,
) -> Result<ForkchoiceUpdatedRequest, RpcErrorResponse> {
    // just extract forkchoicestate
    let params = match request.params.as_array_mut() {
        Some(params_vec) => params_vec,
        None => {
            tracing::error!("Could not serialize fcU's params into a vec.");
            return Err(RpcErrorResponse::new(
                json!("Could not serialize fcU's params into a vec."),
                request.id,
            ));
        }
    };

    if params.is_empty() {
        tracing::error!("CL fcU request does not have the required param.");
        return Err(RpcErrorResponse::new(
            json!("fcU request does not have the required param."),
            request.id,
        ));
    }

    // [forkchoiceState, Option<payloadAttributes>]

    let fork_choice_state: ForkchoiceState = match serde_json::from_value(params[0].take()) {
        Ok(fork_choice_state) => fork_choice_state,
        Err(e) => {
            tracing::error!("Could not serialize ForkchoiceState from fcU: {}", e);
            return Err(RpcErrorResponse::new(
                json!("Could not serialize ForkchoiceState."),
                request.id,
            ));
        }
    };

    if params.len() == 2 {
        return Ok(ForkchoiceUpdatedRequest {
            fork_choice_state,
            payload_attributes: Some(params[1].take()),
        });
    }

    Ok(ForkchoiceUpdatedRequest {
        fork_choice_state,
        payload_attributes: None,
    })
}

fn parse_result_as_value(resp: &str) -> Result<serde_json::Value, ParseError> {
    // todo: maybe serialize directly into T?
    let mut j = match serde_json::from_str::<serde_json::Value>(resp) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Error deserializing response: {}", e);
            return Err(ParseError::InvalidJson);
        }
    };

    if let Some(error) = j.get("error") {
        tracing::error!("Response has error field: {}", error);
        return Err(ParseError::ElError);
    }

    let result = match j.get_mut("result") {
        Some(result) => result,
        None => {
            tracing::error!("Response has no result field");
            return Err(ParseError::ResultNotFound);
        }
    };

    Ok(result.take())
}

fn parse_result<T: serde::de::DeserializeOwned>(resp: &str) -> Result<T, ParseError> {
    // todo: maybe serialize directly into T?
    let result = parse_result_as_value(resp)?;

    match serde_json::from_value::<T>(result) {
        Ok(serialized) => Ok(serialized),
        Err(e) => {
            tracing::error!(
                "Couldn't deserialize response from node to type {}: {}",
                type_name::<T>(),
                e
            );
            Err(ParseError::CouldNotCastToType)
        }
    }
}

async fn make_auth_request(
    node: &Arc<AuthNode>,
    payload: &EngineRpcRequest,
    jwt_secret: String,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let res = node
        .client
        .post(&node.url)
        .header("Authorization", format!("Bearer {}", jwt_secret))
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result_as_value(&res)
        .map_err(|e| format!("Parse error while making request to auth node: {:?}", e))?)
}

async fn make_auth_request_serialize<T: serde::de::DeserializeOwned>(
    node: &Arc<AuthNode>,
    payload: &EngineRpcRequest,
    jwt_secret: String,
) -> Result<T, Box<dyn Error>> {
    let res = node
        .client
        .post(&node.url)
        .header("Authorization", format!("Bearer {}", jwt_secret))
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result::<T>(&res)
        .map_err(|e| format!("Parse error while making request to auth node: {:?}", e))?)
}

async fn make_unauth_request<T: serde::de::DeserializeOwned>(
    node: &Arc<Node>,
    payload: &GeneralRpcRequest,
) -> Result<T, Box<dyn Error>> {
    let res = node
        .client
        .post(&node.url)
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result::<T>(&res)
        .map_err(|e| format!("Parse error while making request to unauth node: {:?}", e))?)
}

async fn get_new_payload_with_retry(state: Arc<State>, block_hash: &H256) -> Option<PayloadStatus> {
    for i in 1..11 {
        if let Some(payload_status) = state.new_payload_cache.read().await.peek(block_hash) {
            tracing::debug!("Got newPayload for client on {}st try.", i);
            return Some(payload_status.clone());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    None
}

async fn get_fcu_with_retry(
    state: Arc<State>,
    forkchoice_state: &ForkchoiceState,
) -> Option<PayloadStatus> {
    for i in 1..6 {
        if let Some(payload_status) = state.fcu_cache.read().await.peek(forkchoice_state) {
            tracing::debug!("Got fcU for client on {}st try.", i);
            return Some(payload_status.clone());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    None
}

async fn canonical_newpayload(
    request: EngineRpcRequest,
    state: Arc<State>,
    jwt_secret: String,
) -> Result<RpcResponse, RpcErrorResponse> {
    // send req to node
    let payloadstatus_result: PayloadStatus =
        make_auth_request_serialize(&state.auth_node, &request, jwt_secret)
            .await
            .map_err(|e| {
                RpcErrorResponse::new(json!(format!("Error querying EL: {:?}", e)), request.id)
            })?;

    let id = request.id;
    let block_hash = new_payload_serializer(request)?
        .execution_payload
        .block_hash();

    state
        .new_payload_cache
        .write()
        .await
        .push(block_hash, payloadstatus_result.clone());
    tracing::debug!("Cached newPayload from canonical node");

    Ok(RpcResponse::new(json!(payloadstatus_result), id))
}

async fn client_newpayload(
    request: EngineRpcRequest,
    state: Arc<State>,
) -> Result<RpcResponse, RpcErrorResponse> {
    let id = request.id;
    let request_execution_payload = new_payload_serializer(request.clone())?;

    match get_new_payload_with_retry(
        state.clone(),
        &request_execution_payload.execution_payload.block_hash(),
    )
    .await
    {
        Some(payload_status) => Ok(RpcResponse::new(json!(payload_status), id)),
        None => {
            if state.passthrough_newpayload {
                tracing::debug!("Client newPayload: Did not find in cache, passing to auth node.");
                return pass_to_auth(request, state, None).await;
            }

            // check if hash is OK
            match verify_payload_block_hash(&request_execution_payload.execution_payload) {
                Ok(()) => {
                    // hash check is fine, return SYNCING
                    tracing::warn!("Client newPayload: Did not find in cache, returning SYNCING");
                    Ok(RpcResponse::new(json!(PayloadStatus::new_syncing()), id))
                },
                Err(e) => {
                    tracing::error!("Client newPayload: Did not find in cache and payload block hash verification failed: {}", e);
                    Err(RpcErrorResponse::new(
                        json!("Payload block hash check failed"),
                        id,
                    ))
                },
            }
        }
    }
}

async fn canonical_fcu(
    request: EngineRpcRequest,
    state: Arc<State>,
    jwt_secret: String,
) -> Result<RpcResponse, RpcErrorResponse> {
    // send req to node
    let fcu_result: ForkchoiceUpdatedResponse =
        make_auth_request_serialize(&state.auth_node, &request, jwt_secret)
            .await
            .map_err(|e| {
                RpcErrorResponse::new(json!(format!("Error querying EL: {:?}", e)), request.id)
            })?;

    let id = request.id;
    let forkchoice_state = fcu_serializer(request)?.fork_choice_state;

    state
        .fcu_cache
        .write()
        .await
        .push(forkchoice_state, fcu_result.payload_status.clone());

    tracing::debug!("Cached fcU from canonical node");

    Ok(RpcResponse::new(json!(fcu_result), id))
}

async fn client_fcu(
    request: EngineRpcRequest,
    state: Arc<State>,
) -> Result<RpcResponse, RpcErrorResponse> {
    let id = request.id;
    let fcu_request = fcu_serializer(request.clone())?;

    match get_fcu_with_retry(state.clone(), &fcu_request.fork_choice_state).await {
        Some(payload_status) => {
            // check if they want to build a block
            if fcu_request.payload_attributes.is_some() {
                if payload_status.status == PayloadStatusStatus::Valid {
                    // pass along to EL since the status would be VALID
                    let fcu_result = make_auth_request(
                        &state.auth_node,
                        &request,
                        make_jwt(&state.auth_node.jwt_secret, &chrono::Utc::now().timestamp()),
                    )
                    .await
                    .map_err(|e| {
                        RpcErrorResponse::new(
                            json!(format!("Error querying EL: {:?}", e)),
                            request.id,
                        )
                    })?;

                    return Ok(RpcResponse::new(json!(fcu_result), id));
                } else {
                    tracing::warn!("Tried passing client CL payloadAttributes but cached EL response is not VALID");
                    return Ok(RpcResponse::new(json!(ForkchoiceUpdatedResponse{ payload_status: PayloadStatus::new_syncing(), payload_id: None }), id));
                }
            }
            // don't want to build a block
            Ok(RpcResponse::new(json!(ForkchoiceUpdatedResponse{ payload_status, payload_id: None }), id))
        }
        None => {
            tracing::warn!("Client newPayload: Did not find in cache, returning SYNCING");
            Ok(RpcResponse::new(json!(ForkchoiceUpdatedResponse{ payload_status: PayloadStatus::new_syncing(), payload_id: None }), id))
        }
    }
}

async fn pass_to_auth(
    request: EngineRpcRequest,
    state: Arc<State>,
    jwt_secret: Option<String>,
) -> Result<RpcResponse, RpcErrorResponse> {
    // pass this to the EL regardless of client or canonical
    let res: Result<serde_json::Value, Box<dyn Error>>;
    if let Some(jwt_secret) = jwt_secret {
        res = make_auth_request(&state.auth_node, &request, jwt_secret).await;
    } else {
        res = make_auth_request(
            &state.auth_node,
            &request,
            make_jwt(&state.auth_node.jwt_secret, &chrono::Utc::now().timestamp()),
        )
        .await;
    }

    match res {
        Ok(el_res) => {
            Ok(RpcResponse::new(el_res, request.id))
        }
        Err(e) => {
            tracing::error!("{:?} request failed: {}", request.method, e);
            Err(RpcErrorResponse::new(
                json!(format!("Request failed: {}", e)),
                request.id,
            ))
        }
    }
}

async fn handle_canonical_engine(
    request: EngineRpcRequest,
    state: Arc<State>,
    jwt_secret: String,
) -> Result<RpcResponse, RpcErrorResponse> {
    match request.method {
        EngineMethod::engine_forkchoiceUpdatedV1
        | EngineMethod::engine_forkchoiceUpdatedV2
        | EngineMethod::engine_forkchoiceUpdatedV3 => {
            canonical_fcu(request, state, jwt_secret).await
        }
        EngineMethod::engine_newPayloadV1
        | EngineMethod::engine_newPayloadV2
        | EngineMethod::engine_newPayloadV3 => {
            canonical_newpayload(request, state, jwt_secret).await
        }
        EngineMethod::engine_getPayloadV1
        | EngineMethod::engine_getPayloadV2
        | EngineMethod::engine_getPayloadV3
        | EngineMethod::engine_exchangeCapabilities
        | EngineMethod::engine_exchangeTransitionConfigurationV1
        | EngineMethod::engine_getPayloadBodiesByHashV1
        | EngineMethod::engine_getPayloadBodiesByRangeV1 => {
            pass_to_auth(request, state, Some(jwt_secret)).await
        }
    }
}

async fn handle_client_engine(
    request: EngineRpcRequest,
    state: Arc<State>,
) -> Result<RpcResponse, RpcErrorResponse> {
    match request.method {
        EngineMethod::engine_forkchoiceUpdatedV1
        | EngineMethod::engine_forkchoiceUpdatedV2
        | EngineMethod::engine_forkchoiceUpdatedV3 => client_fcu(request, state).await,
        EngineMethod::engine_newPayloadV1
        | EngineMethod::engine_newPayloadV2
        | EngineMethod::engine_newPayloadV3 => client_newpayload(request, state).await,
        EngineMethod::engine_getPayloadV1
        | EngineMethod::engine_getPayloadV2
        | EngineMethod::engine_getPayloadV3
        | EngineMethod::engine_exchangeCapabilities
        | EngineMethod::engine_exchangeTransitionConfigurationV1
        | EngineMethod::engine_getPayloadBodiesByHashV1
        | EngineMethod::engine_getPayloadBodiesByRangeV1 => {
            pass_to_auth(request, state, None).await
        }
    }
}

async fn handle_generic_request(
    request: GeneralRpcRequest,
    state: Arc<State>,
) -> Result<RpcResponse, RpcErrorResponse> {
    let res = make_unauth_request(&state.unauth_node, &request).await;

    match res {
        Ok(el_res) => {
            Ok(RpcResponse::new(el_res, request.id))
        }
        Err(e) => {
            tracing::error!("{:?} request failed: {}", request.method, e);
            Err(RpcErrorResponse::new(
                json!(format!("Request failed: {}", e)),
                request.id,
            ))
        }
    }
}

async fn canonical_route_all(
    TypedHeader(jwt): TypedHeader<Authorization<Bearer>>,
    Extension(state): Extension<Arc<State>>,
    extract::Json(request): extract::Json<GeneralRpcRequest>,
) -> Result<extract::Json<RpcResponse>, extract::Json<RpcErrorResponse>> {
    let jwt_secret = jwt.token().to_string();

    if let Ok(engine_request) = EngineRpcRequest::from_general(&request) {
        return handle_canonical_engine(engine_request, state, jwt_secret).await.map(extract::Json).map_err(extract::Json);
    }
    handle_generic_request(request, state).await.map(extract::Json).map_err(extract::Json)
}

async fn client_route_all(
    Extension(state): Extension<Arc<State>>,
    extract::Json(request): extract::Json<GeneralRpcRequest>,
) -> Result<extract::Json<RpcResponse>, extract::Json<RpcErrorResponse>> {
    if let Ok(engine_request) = EngineRpcRequest::from_general(&request) {
        return handle_client_engine(engine_request, state).await.map(extract::Json).map_err(extract::Json);
    }
    handle_generic_request(request, state).await.map(extract::Json).map_err(extract::Json)
}

#[tokio::main]
async fn main() {
    let matches = clap::App::new("openexecution")
        .version("0.1.0")
        .author("TennisBowling <tennisbowling@tennisbowling.com>")
        .about(
            "OpenExecution is a program that lets you control multiple CL's with one canonical CL",
        )
        .setting(clap::AppSettings::ColoredHelp)
        .long_version(
            "OpenExecution version 0.1.0 by TennisBowling <tennisbowling@tennisbowling.com>",
        )
        .arg(
            clap::Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .takes_value(true)
                .default_value("7000"),
        )
        .arg(
            clap::Arg::with_name("jwt-secret")
                .long("jwt-secret")
                .value_name("JWT")
                .help("Path to JWT secret file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("listen-addr")
                .long("listen-addr")
                .value_name("LISTEN")
                .help("Address to listen on")
                .takes_value(true)
                .default_value("0.0.0.0"),
        )
        .arg(
            clap::Arg::with_name("log-level")
                .long("log-level")
                .value_name("LOG")
                .help("Log level")
                .takes_value(true)
                .default_value("info"),
        )
        .arg(
            clap::Arg::with_name("node")
                .long("node")
                .value_name("NODE")
                .help("EL node to connect to for engine_ requests")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("unauth-node")
                .long("unauth-node")
                .value_name("unauth_node")
                .help("unauth EL node to connect to (for non-engine_ requests, such as eth_ requests)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("log-file")
                .long("log-file")
                .value_name("log-path")
                .help("Path to log file")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("passthrough-newpayload")
                .long("passthrough-newpayload")
                .value_name("passthrough-newpayload")
                .help("Pass through client newPayload requests to the auth node if not found in the cache (may present a DoS risk).")
                .long_help("Pass through client newPayload requests to the auth node if not found in the cache (may present a DoS risk). The DoS risk stems from
                the possibility of the client requesting validation of many/old payloads that openexecution doesn't have cached.")
                .takes_value(true)
                .default_value("false")
        )
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let jwt_secret = matches.value_of("jwt-secret").unwrap();
    let listen_addr = matches.value_of("listen-addr").unwrap();
    let log_level = matches.value_of("log-level").unwrap();
    let node = matches.value_of("node").unwrap();
    let unauth_node = matches.value_of("unauth-node").unwrap();
    let passthrough_newpayload = matches.value_of("passthrough-newpayload").unwrap();

    let passthrough_newpayload = match passthrough_newpayload.parse::<bool>() {
        Ok(passthrough_newpayload) => {
            if passthrough_newpayload {
                tracing::warn!("Enabling newPayload passthrough exposes you to a DoS risk.");
            }
            passthrough_newpayload
        },
        Err(_) => {
            tracing::error!("Could not parse passthrough-newpayload as true or false.");
            return;
        },
    };

    
    let filter_string = format!("{},hyper=info", log_level);
    
    let filter = EnvFilter::try_new(filter_string)
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(filter).finish();
    
    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");
    tracing::info!("Starting openexecution version {VERSION}");

    let jwt_secret = std::fs::read_to_string(jwt_secret);
    if let Err(e) = jwt_secret {
        tracing::error!("Unable to read JWT secret: {}", e);
        std::process::exit(1);
    }
    let jwt_secret = jwt_secret.unwrap();

    let jwt_secret = jwt_secret.trim().to_string();

    // check if jwt_secret starts with "0x" and remove it if it does
    let jwt_secret = jwt_secret
        .strip_prefix("0x")
        .unwrap_or(&jwt_secret)
        .to_string();

    let jwt_secret = hex::decode(jwt_secret);
    if let Err(e) = jwt_secret {
        tracing::error!("Unable to decode JWT secret: {}", e);
        std::process::exit(1);
    }
    let jwt_secret = jwt_secret.unwrap();

    let jwt_secret = jsonwebtoken::EncodingKey::from_secret(&jwt_secret);

    tracing::info!("Loaded JWT secret");

    let auth_node = Arc::new(AuthNode {
        client: reqwest::Client::new(),
        url: node.to_string(),
        jwt_secret: Arc::new(jwt_secret),
    });
    let unauth_node = Arc::new(Node {
        client: reqwest::Client::new(),
        url: unauth_node.to_string(),
    });
    let fcu_cache = RwLock::new(LruCache::new(NonZeroUsize::new(64).unwrap()));
    let new_payload_cache = RwLock::new(LruCache::new(NonZeroUsize::new(64).unwrap()));

    let state = Arc::new(State {
        auth_node,
        unauth_node,
        passthrough_newpayload,
        fcu_cache,
        new_payload_cache,
    });

    let app = Router::new()
        .route("/", axum::routing::post(client_route_all))
        .route("/canonical", axum::routing::post(canonical_route_all))
        .layer(Extension(state.clone()))
        .layer(DefaultBodyLimit::disable()); // no body limit since some requests can be quite large

    let addr = format!("{}:{}", listen_addr, port);
    let addr: SocketAddr = addr.parse().unwrap();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("Unable to bind to {}: {}", addr, e);
            return;
        }
    };
    tracing::info!("Listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
