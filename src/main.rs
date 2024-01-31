mod types;
mod keccak;
mod verify_hash;
use std::error::Error;
use std::{sync::Arc, time::Duration};
use ethereum_types::H256;
use serde_json::json;
use verify_hash::*;
use types::*;
use jsonwebtoken::{self, Validation};
use axum::{
    self, extract::DefaultBodyLimit, http::StatusCode, response::IntoResponse,
    Router,
};
use std::any::type_name;


const DEFAULT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;
const VERSION: &str = "0.0.1";

fn make_jwt(jwt_secret: &Arc<jsonwebtoken::EncodingKey>, timestamp: &i64) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(DEFAULT_ALGORITHM),
        &Claims {
            iat: timestamp.to_owned(),
        },
        &jwt_secret,
    )
    .unwrap()
}

fn new_payload_serializer(mut request: RpcRequest) -> Result<NewPayloadRequest, RpcErrorResponse> {

    let params = match request.params.as_array_mut() {
        Some(params_vec) => params_vec,
        None => {
            tracing::error!("Could not serialize newPayload's params into a vec.");
            return Err(RpcErrorResponse::new(json!("Could not serialize newPayload's params into a vec."), request.id));
        },
    };

    if request.method == EngineMethod::engine_newPayloadV3 {
        // params will have 3 fields: [ExecutionPayloadV3, expectedBlobVersionedHashes, ParentBeaconBlockRoot]
        if params.len() != 3 {
            tracing::error!("newPayloadV3's params did not have 3 elements.");
            return Err(RpcErrorResponse::new(json!("newPayloadV3's params did not have 3 elements."), request.id));
        }

        let execution_payload: ExecutionPayload = match serde_json::from_value(params[0].take()) {     // direct getting is safe here since we checked that we have least 3 elements
            Ok(execution_payload) => execution_payload,
            Err(e) => {
                tracing::error!("Could not serialize ExecutionPayload from newPayloadV3: {}", e);
                return Err(RpcErrorResponse::new(json!("Could not serialize ExecutionPayload."), request.id));
            },
        };

        let versioned_hashes: Vec<H256> = match serde_json::from_value(params[1].take()) {
            Ok(versioned_hashes) => versioned_hashes,
            Err(e) => {
                tracing::error!("Could not serialize VersionedHashes from newPayloadV3: {}", e);
                return Err(RpcErrorResponse::new(json!("Could not serialize Versioned Hashes."), request.id));
            }
        };

        let parent_beacon_block_root: H256 = match serde_json::from_value(params[2].take()) {
            Ok(parent_beacon_block_root) => parent_beacon_block_root,
            Err(e) => {
                tracing::error!("Could not serialize ParentBeaconBlockRoot from newPayloadV3: {}", e);
                return Err(RpcErrorResponse::new(json!("Could not serialize ParentBeaconBlockRoot."), request.id));
            }
        };

        return Ok(NewPayloadRequest{ execution_payload, expected_blob_versioned_hashes: Some(versioned_hashes), parent_beacon_block_root: Some(parent_beacon_block_root) });
    }

    // parmas will just have [ExecutionPayloadV1 | ExecutionPayloadV2]

    if params.len() != 1 {
        tracing::error!("newPayloadV1|2's params did not have anything or something went wrong (newPayloadV1|2 called with more than just 1 param (ExecutionPayload).");
        return Err(RpcErrorResponse::new(json!("newPayloadV1|2's params did not have anything."), request.id));
    }

    let execution_payload: ExecutionPayload = match serde_json::from_value(params[0].take()) {
        Ok(execution_payload) => execution_payload,
        Err(e) => {
            tracing::error!("Could not serialize ExecutionPayload from newPayloadV1|2: {}", e);
            return Err(RpcErrorResponse::new(json!("Could not serialize ExecutionPayload."), request.id));
        },
    };

    Ok(NewPayloadRequest { execution_payload, expected_blob_versioned_hashes: None, parent_beacon_block_root: None })

}

fn fcu_serializer(mut request: RpcRequest) -> Result<ForkchoiceUpdatedRequest, RpcErrorResponse> {      // just extract forkchoicestate
    let params = match request.params.as_array_mut() {
        Some(params_vec) => params_vec,
        None => {
            tracing::error!("Could not serialize fcU's params into a vec.");
            return Err(RpcErrorResponse::new(json!("Could not serialize fcU's params into a vec."), request.id));
        },
    };

    if params.len() < 1 {
        tracing::error!("CL fcU request had less than 1 param.");
        return Err(RpcErrorResponse::new(json!("fcU request had less than 1 param."), request.id));
    }

    // [forkchoiceState, Option<payloadAttributes>]

    let fork_choice_state: ForkchoiceState = match serde_json::from_value(params[0].take()) {
        Ok(fork_choice_state) => fork_choice_state,
        Err(e) => {
            tracing::error!("Could not serialize ForkchoiceState from fcU: {}", e);
            return Err(RpcErrorResponse::new(json!("Could not serialize ForkchoiceState."), request.id));
        }
    };

    if params.len() == 2 {
        return Ok(ForkchoiceUpdatedRequest{ fork_choice_state, payload_attributes: Some(params[1].take()) });
    }

    Ok(ForkchoiceUpdatedRequest { fork_choice_state, payload_attributes: None })

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

    if let Some(error)= j.get("error") {
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
        Ok(serialized) => {
            Ok(serialized)
        },
        Err(e) => {
            tracing::error!("Couldn't deserialize response from node to type {}: {}", type_name::<T>(), e);
            Err(ParseError::CouldNotCastToType)
        }

    }
}

async fn make_auth_request(
    node: &Arc<AuthNode>,
    payload: &RpcRequest,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let jwt = make_jwt(&node.jwt_secret, &chrono::Utc::now().timestamp());

    let res = node
        .client
        .post(&node.url)
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result_as_value(&res).map_err(|e| format!("Parse error while making request to auth node: {:?}", e))?)
}

async fn make_auth_request_serialize<T: serde::de::DeserializeOwned>(
    node: &Arc<AuthNode>,
    payload: &RpcRequest,
) -> Result<T, Box<dyn Error>> {
    let jwt = make_jwt(&node.jwt_secret, &chrono::Utc::now().timestamp());

    let res = node
        .client
        .post(&node.url)
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result::<T>(&res).map_err(|e| format!("Parse error while making request to auth node: {:?}", e))?)
}

async fn make_unauth_request<T: serde::de::DeserializeOwned>(node: &Arc<Node>, payload: &RpcRequest) -> Result<T, Box<dyn Error>> {
    let res = node 
        .client
        .post(&node.url)
        .header("Content-Type", "application/json")
        .body(payload.as_bytes())
        .send()
        .await?
        .text()
        .await?;

    Ok(parse_result::<T>(&res).map_err(|e| format!("Parse error while making request to unauth node: {:?}", e))?)
}

async fn get_new_payload_with_retry(state: Arc<State>, block_hash: &H256) -> Option<PayloadStatus> {
    for i in 1..6 {
        if let Some(payload_status) = state.new_payload_cache.read().await.peek(block_hash) {
            tracing::debug!("Got newPayload for client on {}st try.", i);
            return Some(payload_status.clone());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    tracing::debug!("Could not get newPayload for client.");
    None
}

async fn get_fcu_with_retry(state: Arc<State>, forkchoice_state: &ForkchoiceState) -> Option<PayloadStatus> {
    for i in 1..6 {
        if let Some(payload_status) = state.fcu_cache.read().await.peek(forkchoice_state) {
            tracing::debug!("Got fcU for client on {}st try.", i);
            return Some(payload_status.clone());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    tracing::debug!("Could not get fcU for client.");
    None
}

async fn canonical_newpayload(request: RpcRequest, state: Arc<State>) -> Result<RpcResponse, RpcErrorResponse> {
    // send req to node
    let payloadstatus_result: PayloadStatus = make_auth_request_serialize(&state.auth_node, &request).await.map_err(|e| RpcErrorResponse::new(json!(format!("Error querying EL: {:?}", e)), request.id))?;

    let id = request.id;
    let block_hash = new_payload_serializer(request)?.execution_payload.block_hash();

    state.new_payload_cache.write().await.push(block_hash, payloadstatus_result.clone());
    
    Ok(RpcResponse::new(json!(payloadstatus_result), id))
}


async fn client_newpayload(request: RpcRequest, state: Arc<State>) -> Result<RpcResponse, RpcErrorResponse> {

    let id = request.id;
    let request_execution_payload = new_payload_serializer(request)?;

    match get_new_payload_with_retry(state, &request_execution_payload.execution_payload.block_hash()).await {
        Some(payload_status) => {
            Ok(RpcResponse::new(json!(payload_status), id))
        }
        None => {
            // check if hash is OK
            match verify_payload_block_hash(&request_execution_payload.execution_payload) {
                Ok(()) => {     // hash check is fine, return SYNCING
                    tracing::warn!("Client newPayload: Did not find in cache, returning SYNCING");
                    Ok(RpcResponse::new(json!(PayloadStatus::new_syncing()), id))
                },
                Err(e) => {
                    tracing::warn!("Client newPayload: Did not find in cache and payload block hash verification failed: {}", e);
                    Err(RpcErrorResponse::new(json!("Payload block hash check failed"), id))
                }
            }
        }
    }
}

async fn canonical_fcu(request: RpcRequest, state: Arc<State>) -> Result<RpcResponse, RpcErrorResponse> {
    // send req to node
    let fcu_result: ForkchoiceUpdatedResponse = make_auth_request_serialize(&state.auth_node, &request).await.map_err(|e| RpcErrorResponse::new(json!(format!("Error querying EL: {:?}", e)), request.id))?;

    let id = request.id;
    let forkchoice_state = fcu_serializer(request)?.fork_choice_state;

    state.fcu_cache.write().await.push(forkchoice_state, fcu_result.payload_status.clone());
    
    Ok(RpcResponse::new(json!(fcu_result), id))
}

async fn client_fcu(request: RpcRequest, state: Arc<State>) -> Result<RpcResponse, RpcErrorResponse> {      // handle block building

    let id = request.id;
    let forkchoice_state = fcu_serializer(request)?.fork_choice_state;

    match get_fcu_with_retry(state, &forkchoice_state).await {
        Some(payload_status) => {
            Ok(RpcResponse::new(json!(payload_status), id))
        }
        None => {
            tracing::warn!("Client newPayload: Did not find in cache, returning SYNCING");
            Ok(RpcResponse::new(json!(PayloadStatus::new_syncing()), id))
        }
    }
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
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let jwt_secret = matches.value_of("jwt-secret").unwrap();
    let listen_addr = matches.value_of("listen-addr").unwrap();
    let log_level = matches.value_of("log-level").unwrap();
    let node = matches.value_of("node").unwrap();
    let unauth_node = matches.value_of("unauth-node").unwrap();

    let log_level = match log_level {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    // set log level with tracing subscriber
    let subscriber = tracing_subscriber::fmt().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
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

    let jwt_encoding_secret = &jsonwebtoken::EncodingKey::from_secret(&jwt_secret);
    let jwt_decoding_secret = &jsonwebtoken::DecodingKey::from_secret(&jwt_secret);

    tracing::info!("Loaded JWT secret");


    

    /*let app = Router::new()
        .route("/", axum::routing::post(route_all))
        .layer(Extension(router.clone()))
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
    axum::serve(listener, app).await.unwrap();*/
}
