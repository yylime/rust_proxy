# rust-proxy-server

一个精简的 Rust 代理服务器，实现了 **Hysteria2** 和 **AnyTLS** 两种服务端协议，支持 TLS 证书，可直接部署在 Linux 服务器上。

协议实现参考自 [cfal/shoes](https://github.com/cfal/shoes)（MIT 协议，见 [NOTICE](./NOTICE)），本仓库做了裁剪：去掉了代理链/规则引擎，所有流量直接转发到目标地址。

## 支持的协议

- **Hysteria2**（QUIC / HTTP3）：密码鉴权、TCP 流转发、UDP relay（含分片）
- **AnyTLS**（TLS + 多路复用）：SHA256 密码鉴权、会话多路复用、填充混淆、UDP-over-TCP（UoT v1/v2）

## 编译

需要 Rust 1.86+（本仓库依赖已固定兼容 1.86）：

```bash
cargo build --release
```

产物：`target/release/rust-proxy-server`

## 配置与运行

参考 [config.example.yaml](./config.example.yaml)：

```yaml
log_level: info
servers:
  - type: hysteria2
    listen: "0.0.0.0:443"
    password: "your-hy2-password"
    udp_enabled: true
    cert: "/etc/ssl/fullchain.pem"
    key: "/etc/ssl/privkey.pem"

  - type: anytls
    listen: "0.0.0.0:8443"
    cert: "/etc/ssl/fullchain.pem"
    key: "/etc/ssl/privkey.pem"
    udp_enabled: true
    users:
      - name: user1
        password: "your-anytls-password"
```

运行：

```bash
rust-proxy-server -c config.yaml
```

说明：

- `cert`/`key` 不填时会自动生成内存自签证书（仅用于测试，生产环境请使用真实证书）。
- `hysteria2.alpn` 默认 `["h3"]`。
- `anytls.fallback` 可选，配置后鉴权失败的连接会被透明转发到该地址（如本机 Web 服务）。
- AnyTLS 客户端密码即用户配置的 `password`；Hysteria2 客户端密码即 `password`。

## 在 macOS 上打包 linux/amd64

本项目包含 C 依赖（aws-lc-rs、ring），需要交叉 C 工具链，推荐下面几种方式（任选其一）。

### 方式一：Docker（推荐，最简单）

仓库里已带好 [Dockerfile](./Dockerfile) 和脚本：

```bash
chmod +x scripts/build-linux-amd64.sh
./scripts/build-linux-amd64.sh
```

产物为当前目录下的 `rust-proxy-server-linux-amd64`（Linux x86_64，glibc）。

Apple Silicon 上 Docker 会自动用 Rosetta 模拟 amd64 环境，首次构建较慢属正常。

### 方式二：GitHub Actions（不需要本机 Docker）

仓库里已带好 [.github/workflows/build-linux.yml](./.github/workflows/build-linux.yml)：

- 推送普通代码后，在 Actions 页面手动 **Run workflow**，产物作为 artifact 下载；
- 打 `v*` 标签（如 `v0.1.0`）推送时，会自动构建并创建 **GitHub Release**，Release 页面可直接下载二进制：

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 方式三：cargo-zigbuild（不需要 Docker，需要 zig + cmake）

```bash
brew install zig cmake
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu

cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

产物：`target/x86_64-unknown-linux-gnu/release/rust-proxy-server`

想要完全静态的二进制（服务器上不依赖 glibc 版本），可改用 musl 目标：

```bash
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl="zig cc" \
CXX_x86_64_unknown_linux_musl="zig c++" \
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

## 服务器部署（以 systemd 为例）

```ini
[Unit]
Description=rust-proxy-server
After=network.target

[Service]
ExecStart=/usr/local/bin/rust-proxy-server -c /etc/rust-proxy/config.yaml
Restart=on-failure
RestartSec=3
User=nobody

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp rust-proxy-server-linux-amd64 /usr/local/bin/rust-proxy-server
sudo cp config.yaml /etc/rust-proxy/config.yaml
sudo systemctl enable --now rust-proxy
```

## 目录结构

```text
src/
  anytls/        # AnyTLS 协议（类型、填充、多路复用流、会话、server）
  hysteria2.rs   # Hysteria2 server（QUIC/H3、鉴权、TCP/UDP relay）
  tls_config.rs  # TLS 证书加载、自签生成、QUIC/TLS 配置
  resolver.rs    # 直连 DNS 解析（带小缓存）
  udp_relay.rs   # UDP 转发（按目标路由 / 双向拷贝）
  ...            # 移植自 shoes 的公共基础设施
```
