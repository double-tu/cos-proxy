# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

cos-proxy 是一个腾讯云对象存储(COS)的反向代理服务,使用 Go 语言编写。该服务通过内网访问 COS,以节省公网流量费用。项目为单文件架构(`proxy.go`),使用 Docker 容器化部署。

## 开发环境设置

### 本地开发
```bash
# 安装依赖
go mod download

# 创建配置文件
cp demo.env .env
# 编辑 .env 并填入真实的腾讯云配置

# 运行服务
go run proxy.go
```

### Docker 部署
```bash
# 构建并启动容器
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 重新构建镜像
docker-compose build --no-cache
```

### 测试
```bash
# 获取对象 (无需IP白名单)
curl http://localhost:17700/path/to/file.jpg --output test.jpg

# 上传对象 (需要IP在白名单中)
curl -X PUT --data-binary @local-file.txt http://localhost:17700/remote/path/file.txt

# 删除对象 (需要IP在白名单中)
curl -X DELETE http://localhost:17700/path/to/file.jpg

# POST表单上传 (需要IP在白名单中)
curl -X POST -F "key=upload/${filename}" -F "file=@local-file.txt" http://localhost:17700/
```

## 核心架构

### 单体应用结构
整个应用在单个 `proxy.go` 文件中实现,包含以下关键组件:

- **COSProxyHandler** (proxy.go:96): 核心处理器,持有 COS 客户端实例,路由所有 HTTP 请求到对应的处理方法
- **ipWhitelistMiddleware** (proxy.go:52): IP 白名单中间件,对写操作(PUT/POST/DELETE)强制执行 IP 校验,读操作(GET)无限制
- **getLocalIPv4s** (proxy.go:18): 自动检测本机所有非环回 IPv4 地址并添加到白名单

### HTTP 方法处理
- **GET** (proxy.go:127): 下载对象,透传 COS 响应头和响应体
- **PUT** (proxy.go:144): 上传对象,直接转发请求体到 COS
- **DELETE** (proxy.go:156): 删除对象
- **POST** (proxy.go:168): 处理 multipart/form-data 表单上传,支持 `${filename}` 占位符自动替换为上传文件名

### 安全机制
1. **IP 获取策略**: 优先从 `X-Real-IP` 头获取(Nginx 代理场景),回退到 `RemoteAddr`(直连场景)
2. **白名单组成**: 环境变量 `WHITELIST_IPS` 中配置的 IP + 自动检测的本机 IP
3. **错误处理** (proxy.go:212): `handleCOSError` 透传 COS 原始错误响应,包括状态码、头部和 XML 响应体

## 环境变量

必需配置(在 `.env` 文件中):
- `COS_BUCKET_URL_INTERNAL`: COS 存储桶内网域名,格式 `https://bucket-name.cos-internal.ap-region.myqcloud.com`
- `TENCENTCLOUD_SECRET_ID`: 腾讯云 API 密钥 ID
- `TENCENTCLOUD_SECRET_KEY`: 腾讯云 API 密钥
- `WHITELIST_IPS`: 额外的白名单 IP,逗号分隔,如 `8.8.8.8,1.1.1.1`

固定配置:
- 服务监听地址: `:8080` (proxy.go:239)
- Docker 映射端口: `17700:8080` (docker-compose.yaml:15)

## 依赖管理

主要依赖:
- `github.com/tencentyun/cos-go-sdk-v5`: 腾讯云 COS Go SDK v0.7.70

使用国内 Go 代理镜像(Dockerfile:5):
- mirror.ccs.tencentyun.com
- goproxy.cn
- 其他备用镜像

## 部署注意事项

- 必须部署在能访问 COS 内网的腾讯云 CVM 上才能实现内网流量
- 生产环境建议在前面部署 Nginx 处理 HTTPS 和负载均衡,并设置 `X-Real-IP` 头
- 容器使用多阶段构建,最终镜像基于 Alpine Linux,体积小且安全
- POST 表单上传内存限制为 128MB (proxy.go:171)
