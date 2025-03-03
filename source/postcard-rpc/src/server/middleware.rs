//! Middleware types for the server,
//! which interact with the WireTx and WireRx traits.

use serde::Serialize;

use crate::{
    header::{HeaderMode, RpcMessage, VarKeyKind},
    server::{WireTx,WireRx,WireRxErrorKind,AsWireRxErrorKind,Arguments},
};

//////////////////////////////////////////////////////////////////////////////
// WIRE MIDDLEWARE PLUMBING
//////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct BufferedTx<T: WireTx> {
    tx: T,
}

impl <T> BufferedTx<T>
where 
    T: WireTx
{
    pub fn new(tx: T) -> Self {
        Self { tx }
    }
}

impl <T> WireTx for BufferedTx<T>
where 
    T: WireTx
{
    type Error = T::Error;
    type Mode = T::Mode;

    async fn send<M: Serialize + ?Sized>(&self, hdr: <Self::Mode as HeaderMode>::HeaderType, msg: &M) -> Result<(), Self::Error> {
        // println!("BufferedTx::send");
        println!("BufferedTx::send: {:?}", hdr);
        self.tx.send(hdr, msg).await
    }

    async fn send_raw(&self, buf: &[u8]) -> Result<(), Self::Error> {
        println!("BufferedTx::send_raw: {:?}", buf);
        self.tx.send_raw(buf).await
    }

    async fn send_log_str(&self, kkind: VarKeyKind, s: &str) -> Result<(), Self::Error> {
        println!("BufferedTx::send_log_str: {:?}", s);
        self.tx.send_log_str(kkind, s).await
    }

    async fn send_log_fmt<'a>(&self, kkind: VarKeyKind, a: Arguments<'a>) -> Result<(), Self::Error> {
        println!("BufferedTx::send_log_fmt: {:?}", a);
        self.tx.send_log_fmt(kkind, a).await
    }
}

#[derive(Clone)]
pub struct BufferedRx<T: WireRx>
where 
    T: WireRx,
    T::Error: AsWireRxErrorKind,
{
    rx: T,
}

impl <T> BufferedRx<T>
where 
    T: WireRx,
    T::Error: AsWireRxErrorKind,
{
    pub fn new(rx: T) -> Self {
        Self { rx }
    }
}

impl <T> WireRx for BufferedRx<T>
where 
    T: WireRx,
    T::Error: AsWireRxErrorKind,
{
    type Error = T::Error;
    type Mode = T::Mode;

    async fn receive_frame<'a>(&mut self, buf: &'a mut [u8]) -> Result<RpcMessage<'a, Self::Mode>, WireRxErrorKind> {
        match self.rx.receive_frame(buf).await {
            Err(e) => {
                println!("BufferedRx::receive_frame: {:?}", e.as_kind());
                Err(e)
            },
            Ok(result) => {
                println!("BufferedRx::receive_frame: {:?}", &result.header);
                Ok(result)
            }
        }
    }

    async fn receive<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error> 
    {
        match self.rx.receive(buf).await {
            Err(e) => {
                println!("BufferedRx::receive: {:?}", e.as_kind());
                Err(e)
            },
            Ok(result) => {
                println!("BufferedRx::receive: {:?}", &result);
                Ok(result)
            }
        }
    }
}

