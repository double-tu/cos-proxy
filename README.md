# cos-proxy

## 1. 项目概述 (Overview)

`cos-proxy` 是一个专为腾讯云对象存储（COS）设计的反向代理服务。它使用 Go 语言编写，旨在通过腾讯云内网访问 COS 资源，从而帮助用户节省公网流量费用。

此项目的核心价值在于利用云服务器（CVM）与对象存储（COS）之间的高速内网连接。将 `cos-proxy` 部署在 CVM 上后，所有对 COS 的请求都将通过内网进行，避免了因公网下行流量而产生的高昂费用，同时通过内置的安全机制保障数据安全。

## 2. 架构 (Architecture)

服务的工作流程清晰、高效，可以轻松集成到现有架构中。

**工作流程:**
`客户端请求 -> Nginx (可选) -> cos-proxy -> 腾讯云 COS 内网`

**架构解析:**

1.  **客户端请求**: 外部用户或应用发起对资源的访问请求（如上传、下载、删除）。
2.  **Nginx (可选)**: 在生产环境中，建议在 `cos-proxy` 前部署 Nginx 作为网关，负责处理域名、HTTPS 证书和负载均衡，并将真实的用户 IP 通过 `X-Real-IP` 头传递给代理。
3.  **cos-proxy**:
    *   接收来自客户端或 Nginx 的请求。
    *   **IP 白名单验证**: 对于所有写操作（`PUT`, `POST`, `DELETE`），服务会强制检查请求来源的 IP 是否在白名单中。
    *   **与 COS 交互**: 验证通过后，`cos-proxy` 使用腾讯云官方 Go SDK，通过内网域名与 COS 服务进行通信，完成对象的上传、下载或删除。
4.  **腾讯云 COS 内网**: 最终的数据传输在腾讯云的内网中完成，不产生公网流量费用。

## 3. 核心功能 (Features)

*   **完整的对象操作**: 全面支持 `GET` (获取), `PUT` (上传), `DELETE` (删除) 和 `POST` (表单上传) 方法，覆盖了对象存储的核心操作。
*   **S3 分块上传**: 完全兼容 S3 分块上传协议，支持 `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, 和 `AbortMultipartUpload` 操作，适用于大文件上传场景。
*   **POST 表单上传**: 支持标准 `multipart/form-data` 表单上传。您可以在表单 `key` 字段中使用 `${filename}` 占位符，代理会自动将其替换为上传文件的原始名称。
*   **IP 白名单**: 为保障存储桶安全，所有写操作 (`PUT`, `POST`, `DELETE`) 都强制执行 IP 白名单检查。只有来自受信任 IP 的请求才会被允许执行。
*   **智能 IP 获取**: 代理会优先从 `X-Real-IP` HTTP 头获取客户端 IP（完美兼容 Nginx），如果该头不存在，则自动回退到请求的 `RemoteAddr`，确保在各种部署场景下都能准确识别来源 IP。
*   **自动白名单**: 服务启动时，会自动检测并添加运行该服务的主机的所有本地 IPv4 地址到白名单中，简化了服务器本机访问的配置。
*   **容器化部署**: 项目提供了 `Dockerfile` 和 `docker-compose.yaml`，支持使用 Docker 进行一键构建和部署，极大简化了部署流程。

## 4. 快速开始 (Quick Start)

按照以下步骤，您可以在几分钟内启动并运行 `cos-proxy` 服务。

**1. 克隆项目**
```bash
git clone https://github.com/your-username/cos-proxy.git
cd cos-proxy
```

**2. 创建并编辑配置文件**
从模板文件复制一份新的环境配置文件。
```bash
cp .env.demo .env
```
然后，使用文本编辑器打开 `.env` 文件，并填入您的腾讯云配置信息。

**3. 填写配置**
编辑 `.env` 文件，填入以下内容：
```dotenv
# COS 存储桶的内网访问域名
COS_BUCKET_URL_INTERNAL=https://your-bucket-name.cos-internal.ap-guangzhou.myqcloud.com

# 腾讯云 API 密钥
TENCENTCLOUD_SECRET_ID=您的SecretId
TENCENTCLOUD_SECRET_KEY=您的SecretKey

# 额外的白名单 IP，多个 IP 用逗号分隔 (例如: 8.8.8.8,1.1.1.1)
WHITELIST_IPS=
```

**4. 启动服务**
使用 `docker-compose` 一键启动服务。
```bash
docker-compose up -d
```
服务将在后台启动，并监听在 `17700` 端口。

## 5. 配置 (Configuration)

`cos-proxy` 的所有配置均通过 `.env` 文件中的环境变量进行管理。

| 环境变量                  | 描述                                                                                                                               | 示例值                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `COS_BUCKET_URL_INTERNAL` | **(必需)** 您的 COS 存储桶的**内网**访问域名。请务必使用 `cos-internal` 域名以确保流量通过内网。                                       | `https://example-1250000000.cos-internal.ap-guangzhou.myqcloud.com` |
| `TENCENTCLOUD_SECRET_ID`  | **(必需)** 用于访问腾讯云 API 的 Secret ID。建议使用子账号密钥以遵循最小权限原则。                                                     | `AKIDxxxxxxxxxxxxxxxxxxxxxxxxxxxx`                                  |
| `TENCENTCLOUD_SECRET_KEY` | **(必需)** 用于访问腾讯云 API 的 Secret Key。                                                                                      | `yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy`                                  |
| `WHITELIST_IPS`           | **(可选)** 额外的 IP 白名单列表，用于允许指定的外部 IP 执行写操作。多个 IP 地址之间请用英文逗号 `,` 分隔。服务所在主机的 IP 会被自动添加。 | `8.8.8.8,1.1.1.1`                                                   |

## 6. API 使用示例 (API Usage)

假设服务部署在 `http://127.0.0.1:17700`。

**获取对象 (GET)**
```bash
curl http://127.0.0.1:17700/path/to/your/object.jpg --output object.jpg
```

**上传对象 (PUT)**
```bash
# 需要确保您的公网 IP 已被添加到 WHITELIST_IPS
curl -X PUT --data-binary @"/path/to/local/file.txt" http://127.0.0.1:17700/remote/path/file.txt
```

**删除对象 (DELETE)**
```bash
# 需要确保您的公网 IP 已被添加到 WHITELIST_IPS
curl -X DELETE http://127.0.0.1:17700/path/to/your/object.jpg
```

**通过表单上传对象 (POST)**
这是最灵活的上传方式，支持动态文件名。
```bash
# -F "key=upload/images/${filename}"  -> COS 中的存储路径，${filename} 会被替换为 "my-photo.png"
# -F "file=@/path/to/local/my-photo.png" -> 本地文件
# 需要确保您的公网 IP 已被添加到 WHITELIST_IPS
curl -X POST \
  -F "key=upload/images/${filename}" \
  -F "file=@/path/to/local/my-photo.png" \
  http://127.0.0.1:17700/
```

## 7. 注意事项 (Notes)

*   **部署环境**: 为了实现节省流量费用的目的，此代理服务**必须**部署在能够通过内网访问 COS 的腾讯云 CVM 上。部署在其他云服务商或本地计算机上将无法利用内网连接。
*   **安全**: IP 白名单是保障您存储桶写操作安全的关键。请务必将所有需要上传或修改文件的服务器 IP 添加到 `.env` 文件的 `WHITELIST_IPS` 变量中。切勿将不必要的 IP 加入白名单。