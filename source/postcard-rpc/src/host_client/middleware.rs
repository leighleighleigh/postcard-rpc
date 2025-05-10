//! Middleware types for HostClient Wires (WireTx/WireRx traits)

use core::{default, future::Future};

use serde::Serialize;
use crate::{
    header::{HeaderMode,RpcMessage,VarKeyKind,Addressable,Header},
    host_client::{WireTx,WireRx},
};

use core::marker::PhantomData;

#[derive(Clone)]
pub struct ClientBufferedTx<T: WireTx, Mode: HeaderMode>
{
    tx: T,
    _pd: PhantomData<Mode>,
}

impl <T,Mode> ClientBufferedTx<T,Mode>
where 
    T: WireTx,
    Mode: HeaderMode + Send
{
    pub fn new(tx: T) -> Self {
        Self { tx , _pd: PhantomData }
    }
}

impl <T,Mode> WireTx for ClientBufferedTx<T,Mode>
where 
    T: WireTx,
    Mode: HeaderMode + Send
{
    type Error = T::Error;

    async fn send(&mut self, data: Vec<u8>) -> Result<(), Self::Error>
    {
        println!("ClientBufferedTx::send: {:?}", data);
        // this buffered writer will peek into the data, and potentially modify it!
        let mut buf = data.clone();
        let mut msg = RpcMessage::<Mode>::from_vec(&mut buf).unwrap();
        msg.header = msg.header.with_src(<<Mode as HeaderMode>::HeaderType as Addressable>::localhost());
        println!("ClientBufferedTx::send: {:?}", msg.header);
        // serialize to buf
        let new_data = msg.to_vec();
        self.tx.send(new_data).await
    }
}

#[derive(Clone)]
pub struct ClientBufferedRx<T: WireRx,Mode: HeaderMode> {
    rx: T,
    _pd: PhantomData<Mode>,
}

impl <T,Mode> ClientBufferedRx<T,Mode>
where 
    T: WireRx,
    Mode: HeaderMode + Send
{
    pub fn new(rx: T) -> Self {
        Self { rx , _pd: PhantomData }
    }
}

impl <T,Mode> WireRx for ClientBufferedRx<T,Mode>
where 
    T: WireRx,
    Mode: HeaderMode + Send
{
    type Error = T::Error;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error>
    {
        let data = self.rx.receive().await?;
        println!("ClientBufferedRx::receive: {:?}", data);
        // this buffered reader will peek into the data, and potentially modify it!
        let mut buf = data.clone();
        let mut msg = RpcMessage::<Mode>::from_vec(&mut buf).unwrap();
        println!("ClientBufferedRx::receive: {:?}", msg.header);
        // replace the dst address with 00's
        msg.header = msg.header.with_dst(<<Mode as HeaderMode>::HeaderType as Addressable>::localhost());
        Ok(data)
    }
}