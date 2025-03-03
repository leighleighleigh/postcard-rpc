use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use postcard_schema::Schema;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use postcard_rpc::{
    define_dispatch, endpoints,
    header::{Unicast, UnicastHeader, Broadcast, BroadcastHeader, VarSeqKind, HeaderMode, Addressable},
    host_client::test_channels as client,
    server::{
        impls::test_channels::{
            dispatch_impl::{
                new_server_raw, spawn_fn, Settings, WireSpawnImpl,
            },
            ChannelWireRx, ChannelWireSpawn, ChannelWireTx,
        },
        Dispatch, Sender, SpawnContext,
        middleware::{BufferedTx, BufferedRx},
    },
    topics,
};

#[derive(Serialize, Deserialize, Schema)]
pub struct AReq(pub u8);
#[derive(Serialize, Deserialize, Schema)]
pub struct AResp(pub u8);
#[derive(Serialize, Deserialize, Schema)]
pub struct BReq(pub u16);
#[derive(Serialize, Deserialize, Schema)]
pub struct BResp(pub u32);
#[derive(Serialize, Deserialize, Schema)]
pub struct GReq;
#[derive(Serialize, Deserialize, Schema)]
pub struct GResp;
#[derive(Serialize, Deserialize, Schema)]
pub struct DReq;
#[derive(Serialize, Deserialize, Schema)]
pub struct DResp;
#[derive(Serialize, Deserialize, Schema)]
pub struct EReq;
#[derive(Serialize, Deserialize, Schema)]
pub struct EResp;
#[derive(Serialize, Deserialize, Schema)]
pub struct ZMsg(pub i16);

#[cfg(feature = "alpha")]
#[derive(Serialize, Deserialize, Schema)]
pub struct Message<'a> {
    data: &'a str,
}

#[cfg(not(feature = "alpha"))]
#[derive(Serialize, Deserialize, Schema)]
pub struct Message {
    data: String,
}

#[derive(Serialize, Deserialize, Schema)]
pub struct DoubleMessage<'a, 'b> {
    data1: &'a str,
    data2: &'b str,
}

endpoints! {
    list = ENDPOINT_LIST;
    | EndpointTy        | RequestTy             | ResponseTy            | Path              | Cfg                    |
    | ----------        | ---------             | ----------            | ----              | ---                    |
    | AlphaEndpoint     | AReq                  | AResp                 | "alpha"           |                        |
    | BetaEndpoint      | BReq                  | BResp                 | "beta"            |                        |
    | GammaEndpoint     | GReq                  | GResp                 | "gamma"           |                        |
    | DeltaEndpoint     | DReq                  | DResp                 | "delta"           |                        |
    | EpsilonEndpoint   | EReq                  | EResp                 | "epsilon"         |                        |
    | BorrowEndpoint1   | Message<'a>           | u8                    | "borrow1"         | cfg(feature = "alpha") |
    | BorrowEndpoint2   | ()                    | Message<'a>           | "borrow2"         |                        |
    | BorrowEndpoint3   | Message<'a>           | Message<'b>           | "borrow3"         |                        |
    | BorrowEndpoint4   | DoubleMessage<'a, 'b> | DoubleMessage<'c, 'd> | "borrow4"         |                        |
}

topics! {
    list = TOPICS_IN_LIST;
    direction = postcard_rpc::TopicDirection::ToServer;
    | TopicTy       | MessageTy             | Path      | Cfg                           |
    | ----------    | ---------             | ----      | ---                           |
    | ZetaTopic1    | ZMsg                  | "zeta1"   |                               |
    | ZetaTopic2    | ZMsg                  | "zeta2"   |                               |
    | ZetaTopic3    | ZMsg                  | "zeta3"   |                               |
    | BorrowTopic   | Message<'a>           | "msg1"    | cfg(feature = "alpha")        |
    | BorrowTopic   | DoubleMessage<'a, 'b> | "msg1"    | cfg(not(feature = "alpha"))   |
    | BerpTopic1    | u8                    | "empty"   |                               |
    | BerpTopic2    | ()                    | "empty"   |                               |
}

topics! {
    list = TOPICS_OUT_LIST;
    direction = postcard_rpc::TopicDirection::ToClient;
    | TopicTy           | MessageTy     | Path              |
    | ----------        | ---------     | ----              |
    | ZetaTopic10       | ZMsg          | "zeta10"          |
}

pub struct TestContext {
    pub ctr: Arc<AtomicUsize>,
    pub topic_ctr: Arc<AtomicUsize>,
    pub msg: String,
}

pub struct TestSpawnContext {
    pub ctr: Arc<AtomicUsize>,
    pub topic_ctr: Arc<AtomicUsize>,
}

impl SpawnContext for TestContext {
    type SpawnCtxt = TestSpawnContext;

    fn spawn_ctxt(&mut self) -> Self::SpawnCtxt {
        TestSpawnContext {
            ctr: self.ctr.clone(),
            topic_ctr: self.topic_ctr.clone(),
        }
    }
}


// intercept all requests and responses using a middleware
// type AppMode = Unicast;
type AppMode = Broadcast;
type AppHeader = <AppMode as HeaderMode>::HeaderType;
type AppTx = BufferedTx<ChannelWireTx<AppMode>>;
type AppRx = BufferedRx<ChannelWireRx<AppMode>>;

define_dispatch! {
    app: MiddlewareDispatcher;
    spawn_fn: spawn_fn;
    tx_impl: AppTx;
    hd_mode: AppMode;
    spawn_impl: WireSpawnImpl;
    context: TestContext;

    endpoints: {
        list: crate::ENDPOINT_LIST;

        | EndpointTy        | kind      | handler                   |
        | ----------        | ----      | -------                   |
        | AlphaEndpoint     | async     | test_alpha_handler        |
        | BetaEndpoint      | spawn     | test_beta_handler         |
    };
    topics_in: {
        list: crate::TOPICS_IN_LIST;

        | TopicTy           | kind      | handler               |
        | ----------        | ----      | -------               |
    };
    topics_out: {
        list: TOPICS_OUT_LIST;
    };
}

async fn test_alpha_handler(context: &mut TestContext, _header: AppHeader, body: AReq) -> AResp {
    context.ctr.fetch_add(1, Ordering::Relaxed);
    AResp(body.0)
}

async fn test_beta_handler(
    context: TestSpawnContext,
    header: AppHeader,
    body: BReq,
    out: Sender<AppTx, AppMode>,
) {
    context.ctr.fetch_add(1, Ordering::Relaxed);
    let _ = out
        .reply::<BetaEndpoint>(&header, &BResp(body.0.into()))
        .await;
}


#[tokio::test]
async fn end_to_end() {
    let (client_tx, server_rx) = mpsc::channel(32);
    let (server_tx, client_rx) = mpsc::channel(32);
    let topic_ctr = Arc::new(AtomicUsize::new(0));

    let app = MiddlewareDispatcher::new(
        TestContext {
            ctr: Arc::new(AtomicUsize::new(0)),
            topic_ctr: topic_ctr.clone(),
            msg: String::from("hello"),
        },
        ChannelWireSpawn {},
    );

    let _cwrx = ChannelWireRx::new(server_rx);
    let cwrx = BufferedRx::new(_cwrx);

    let _cwtx = ChannelWireTx::new(server_tx);
    let cwtx = BufferedTx::new(_cwtx);


    let kkind = app.min_key_len();
    let mut server = new_server_raw::<_,AppMode,AppTx,AppRx>(
        app,
        Settings {
            tx: cwtx,
            rx: cwrx,
            buf: 1024,
            kkind,
        },
    );
    tokio::task::spawn(async move {
        server.run().await;
    });

    // let cli = client::new_from_channels::<AppMode>(client_tx, client_rx, VarSeqKind::Seq1);
    let cli = client::new_from_channels_buffered::<AppMode>(client_tx, client_rx, VarSeqKind::Seq1);

    // let from = <<Unicast as HeaderMode>::HeaderType as Addressable>::localhost();
    let addr = <<Broadcast as HeaderMode>::HeaderType as Addressable>::broadcast();

    let resp = cli.send_request_to::<AlphaEndpoint>(addr,&AReq(42)).await.unwrap();
    println!("resp: {:?}", resp.0);
    assert_eq!(resp.0, 42);
 
    let resp = cli.send_request_to::<BetaEndpoint>(addr,&BReq(1234)).await.unwrap();
    println!("resp: {:?}", resp.0);
    assert_eq!(resp.0, 1234);

}