use candid::Principal;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn subaccount_from_principal(principal: &Principal) -> Subaccount {
    let mut subaccount = [0; 32];
    let principal = principal.as_slice();
    subaccount[0] = principal.len() as u8;
    subaccount[1..principal.len() + 1].copy_from_slice(principal);
    subaccount
}

pub fn principal_from_subaccount(subaccount: &Subaccount) -> Principal {
    let len = subaccount[0] as usize;
    Principal::from_slice(&subaccount[1..1 + std::cmp::min(len, 29)])
}

pub fn calc_msgid(caller: &Subaccount, nonce: u32) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(caller);
    hasher.update(&nonce.to_le_bytes());
    let hashed = hasher.finalize();
    // Return XOR of 128 bit chunks of the hashed principal
    let mut id = 0;
    for i in 0..2 {
        id ^= u128::from_le_bytes(hashed[i * 16..(i + 1) * 16].try_into().unwrap_or_default());
    }
    id
}

pub fn read_event_logs(
    events: &serde_json::Value,
) -> Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>, &'static str> {
    if let Some(results) = events
        .as_object()
        .and_then(|x| x.get("result"))
        .and_then(|x| x.as_array())
    {
        let mut data_and_topics = Vec::new();
        for r in results {
            let data = r
                .as_object()
                .and_then(|x| x.get("data"))
                .and_then(|x| x.as_str())
                .and_then(|x| hex::decode(&x[2..]).ok());
            let topics = r
                .as_object()
                .and_then(|x| x.get("topics"))
                .and_then(|x| x.as_array())
                .map(|x| {
                    x.into_iter()
                        .filter_map(|x| x.as_str())
                        .filter_map(|x| hex::decode(&x[2..]).ok())
                        .collect()
                });
            match (data, topics) {
                (Some(data), Some(topics)) => data_and_topics.push((data, topics)),
                (None, _) => return Err("No valid 'result.data' found in JSON"),
                (_, None) => {
                    return Err("No 'result.topics' found in JSON");
                }
            }
        }
        Ok(data_and_topics)
    } else {
        Err("No 'result' found in JSON")
    }
}

pub fn parse_transfer(data: Vec<u8>, topics: Vec<Vec<u8>>) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "from".to_string(),
            kind: ParamType::Address,
            indexed: true,
        },
        EventParam {
            name: "to".to_string(),
            kind: ParamType::Address,
            indexed: true,
        },
        EventParam {
            name: "tokens".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
    ];
    let transfer = Event {
        name: "Transfer".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = topics
        .iter()
        .map(|topic| Hash::from_slice(&topic))
        .collect();
    let rawlog = RawLog { topics, data };

    Ok(transfer.parse_log(rawlog).unwrap())
}

pub fn parse_burn_to_icp(data: Vec<u8>, topics: Vec<Vec<u8>>) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "amount".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
        EventParam {
            name: "principal".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
        EventParam {
            name: "subaccount".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
    ];
    let burn_to_icp = Event {
        name: "BurnToIcp".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = topics
        .iter()
        .map(|topic| Hash::from_slice(&topic))
        .collect();
    let rawlog = RawLog { topics, data };
    burn_to_icp
        .parse_log(rawlog)
        .map_err(|err| format!("{}", err))
}

pub fn parse_burn_to_icp_account_id(
    data: Vec<u8>,
    topics: Vec<Vec<u8>>,
) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "amount".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
        EventParam {
            name: "accountId".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
    ];
    let burn_to_icp_account_id = Event {
        name: "BurnToIcp".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = topics
        .iter()
        .map(|topic| Hash::from_slice(&topic))
        .collect();
    let rawlog = RawLog { topics, data };
    burn_to_icp_account_id
        .parse_log(rawlog)
        .map_err(|err| format!("{}", err))
}

pub fn log_to_map(log: ethabi::Log) -> BTreeMap<String, ethabi::Token> {
    log.params.into_iter().map(|p| (p.name, p.value)).collect()
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[test]
fn test_parse_burn_to_icp() {
    let s = "{\"id\":null,\"jsonrpc\":\"2.0\",\"result\":[{\"address\":\"0x8c283b98edeb405816fd1d321005df4d3aa956ba\",\"blockHash\":\"0x8900bc3dbd462e7a9f76bfac3199729943e677d7d44bd50556b27f935a705fc7\",\"blockNumber\":\"0x93fd3b\",\"data\":\"0x000000000000000000000000000000000000000000000000016345785d8a0000\",\"logIndex\":\"0x32\",\"removed\":false,\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\",\"0x0000000000000000000000002c91e73a358e6f0aff4b9200c8bad0d4739a70dd\",\"0x0000000000000000000000000000000000000000000000000000000000000000\"],\"transactionHash\":\"0xcea897ee46a9fbe6ce6f2945b172ebc224d2871f70b35de35600be9d71a05dd1\",\"transactionIndex\":\"0x1e\"},{\"address\":\"0x8c283b98edeb405816fd1d321005df4d3aa956ba\",\"blockHash\":\"0x8900bc3dbd462e7a9f76bfac3199729943e677d7d44bd50556b27f935a705fc7\",\"blockNumber\":\"0x93fd3b\",\"data\":\"0x0000000000000000000000000000000000000000000000000000000000989680\",\"logIndex\":\"0x33\",\"removed\":false,\"topics\":[\"0x7fe818d2b919ac5cc197458482fab0d4285d783795541be06864b0baa6ac2f5c\",\"0x9e7d426db28fa46d013ad4c9955074e3946ab25203eece542b098f1c02000000\",\"0x0000000000000000000000000000000000000000000000000000000000000000\"],\"transactionHash\":\"0xcea897ee46a9fbe6ce6f2945b172ebc224d2871f70b35de35600be9d71a05dd1\",\"transactionIndex\":\"0x1e\"}]}";
    let value: serde_json::Value = serde_json::from_str(s).unwrap();
    let mut data_and_topics = read_event_logs(&value).unwrap();
    assert_eq!(data_and_topics.len(), 2);
    let (data, topics) = data_and_topics.pop().unwrap();
    let m = log_to_map(parse_burn_to_icp(data, topics).unwrap());
    assert!(m
        .get("amount")
        .cloned()
        .and_then(|x| x.into_uint())
        .is_some());
    assert!(m
        .get("principal")
        .cloned()
        .and_then(|x| x.into_fixed_bytes())
        .is_some());
    assert!(m
        .get("subaccount")
        .cloned()
        .and_then(|x| x.into_fixed_bytes())
        .is_some());
    let (data, topics) = data_and_topics.pop().unwrap();
    let m = log_to_map(parse_transfer(data, topics).unwrap());
    assert!(m
        .get("from")
        .cloned()
        .and_then(|x| x.into_address())
        .is_some());
    assert!(m
        .get("to")
        .cloned()
        .and_then(|x| x.into_address())
        .is_some());
    assert!(m
        .get("tokens")
        .cloned()
        .and_then(|x| x.into_uint())
        .is_some());
}
