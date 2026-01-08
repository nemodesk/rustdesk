use crate::ResultType;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio_socks::{udp::Socks5UdpFramed, IntoTargetAddr, TargetAddr, ToProxyAddrs};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use rand::Rng;

pub enum FramedSocket {
    Direct(UdpFramed<BytesCodec>),
    ProxySocks(Socks5UdpFramed),
}

fn new_socket(addr: SocketAddr, reuse: bool, buf_size: usize) -> Result<Socket, std::io::Error> {
    let socket = match addr {
        SocketAddr::V4(..) => Socket::new(Domain::ipv4(), Type::dgram(), None),
        SocketAddr::V6(..) => Socket::new(Domain::ipv6(), Type::dgram(), None),
    }?;
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuse_port(true).ok();
        socket.set_reuse_address(true).ok();
    }
    // only nonblocking work with tokio, https://stackoverflow.com/questions/64649405/receiver-on-tokiompscchannel-only-receives-messages-when-buffer-is-full
    socket.set_nonblocking(true)?;
    if buf_size > 0 {
        socket.set_recv_buffer_size(buf_size).ok();
    }
    log::debug!(
        "Receive buf size of udp {}: {:?}",
        addr,
        socket.recv_buffer_size()
    );
    if addr.is_ipv6() && addr.ip().is_unspecified() && addr.port() > 0 {
        socket.set_only_v6(false).ok();
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

impl FramedSocket {
    pub async fn new<T: ToSocketAddrs>(addr: T) -> ResultType<Self> {
        Self::new_reuse(addr, false, 0).await
    }

    pub async fn new_reuse<T: ToSocketAddrs>(
        addr: T,
        reuse: bool,
        buf_size: usize,
    ) -> ResultType<Self> {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        Ok(Self::Direct(UdpFramed::new(
            UdpSocket::from_std(new_socket(addr, reuse, buf_size)?.into_udp_socket())?,
            BytesCodec::new(),
        )))
    }

    pub async fn new_proxy<'a, 't, P: ToProxyAddrs, T: ToSocketAddrs>(
        proxy: P,
        local: T,
        username: &'a str,
        password: &'a str,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let framed = if username.trim().is_empty() {
            super::timeout(ms_timeout, Socks5UdpFramed::connect(proxy, Some(local))).await??
        } else {
            super::timeout(
                ms_timeout,
                Socks5UdpFramed::connect_with_password(proxy, Some(local), username, password),
            )
            .await??
        };
        log::trace!(
            "Socks5 udp connected, local addr: {:?}, target addr: {}",
            framed.local_addr(),
            framed.socks_addr()
        );
        Ok(Self::ProxySocks(framed))
    }

    #[inline]
    pub async fn send(
        &mut self,
        msg: &impl Message,
        addr: impl IntoTargetAddr<'_>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();
        // 1. 将原始消息序列化为字节数组
        let mut data = msg.write_to_bytes()?; // 转换为 Vec<u8>

        // 2. 伪装：添加 10 到 50 字节的随机填充
        let mut rng = rand::thread_rng();
        // 使用 u8 类型存储长度，范围限制在 10 到 255 字节（足够用）
        let padding_len_u8: u8 = rng.gen_range(10..=50);

        for _ in 0..padding_len_u8 {
            data.push(rng.gen()); // 填充随机字节
        }

        // 3. 将填充长度作为一个字节拼接到信息的最后
        data.push(padding_len_u8);
        // 现在，数据包结构是：[原始 Protobuf 数据] + [随机噪音] + [一个字节的噪音长度标记]

        let send_data = Bytes::from(data);
        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.send((send_data, addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send((send_data, addr)).await?,
        };
        Ok(())
    }

    // https://stackoverflow.com/a/68733302/1926020
    #[inline]
    pub async fn send_raw(
        &mut self,
        msg: &'static [u8],
        addr: impl IntoTargetAddr<'static>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();

        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.send((Bytes::from(msg), addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send((Bytes::from(msg), addr)).await?,
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        match self {
            Self::Direct(f) => {
                while let Some(res) = f.next().await {
                    match res {
                        Ok((mut data, addr)) => {
                            // --- 增强逻辑：验证并剥离混淆数据 ---
                            if let Some(&padding_len) = data.last() {
                                let p_len = padding_len as usize;
                                // 验证标记：必须在客户端定义的 10-50 范围内
                                // 且数据包总长度必须足以容纳 噪音 + 1字节标记
                                if p_len >= 10 && p_len <= 50 && data.len() > p_len {
                                    let actual_len = data.len() - 1 - p_len;
                                    data.truncate(actual_len);
                                    return Some(Ok((data, addr.into_target_addr().ok()?.to_owned())));
                                }
                            }
                            // 如果不符合上述混淆特征，直接忽略该包，继续循环等待下一个包
                            log::trace!("丢弃未混淆或非法格式的 UDP 包，来自: {:?}", addr);
                            continue;
                        }
                        Err(e) => return Some(Err(anyhow!(e))),
                    }
                }
                None
            },
            Self::ProxySocks(f) => {
                while let Some(res) = f.next().await {
                    match res {
                        Ok((mut data, _)) => {
                            if let Some(&p_len_u8) = data.data.last() {
                                let p_len = p_len_u8 as usize;
                                if p_len >= 10 && p_len <= 50 && data.data.len() > p_len {
                                    let actual_len = data.data.len() - 1 - p_len;
                                    data.data.truncate(actual_len);
                                    return Some(Ok((data.data, data.dst_addr)));
                                }
                            }
                            continue; // 丢弃不合规报文
                        }
                        Err(e) => return Some(Err(anyhow!(e))),
                    }
                }
                None
            },
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        ms: u64,
    ) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        if let Ok(res) =
            tokio::time::timeout(std::time::Duration::from_millis(ms), self.next()).await
        {
            res
        } else {
            None
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        if let FramedSocket::Direct(x) = self {
            if let Ok(v) = x.get_ref().local_addr() {
                return Some(v);
            }
        }
        None
    }
}
