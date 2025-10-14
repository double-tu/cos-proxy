# --- Stage 1: Build ---
# 使用官方的 Golang 镜像作为构建环境
FROM golang:1.22-alpine AS builder

ENV GOPROXY=https://mirror.ccs.tencentyun.com,https://goproxy.cn,https://docker.1panel.live,https://docker-0.unsee.tech,https://docker.m.daocloud.io,https://registry.cyou,direct
ENV GOSUMDB=off
ENV GOPRIVATE=

# 设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum 文件并下载依赖
# 这一步可以利用 Docker 的层缓存，如果依赖没有变化则无需重复下载
COPY go.mod go.sum ./
RUN go mod download

# 复制所有源代码
COPY . .

# 编译应用。CGO_ENABLED=0 创建一个静态链接的二进制文件
# GOOS=linux 指定为 Linux 系统编译
RUN CGO_ENABLED=0 GOOS=linux go build -o /cos-proxy .

# --- Stage 2: Final Image ---
# 使用一个非常小的 Alpine 镜像作为最终镜像
FROM alpine:latest

# Alpine 镜像默认没有根证书，需要安装才能进行 HTTPS 请求
RUN apk --no-cache add ca-certificates

# 将工作目录设置为 /app
WORKDIR /app

# 从构建阶段(builder)复制编译好的二进制文件到当前镜像
COPY --from=builder /cos-proxy .

# 暴露应用监听的端口 (这里是 8080)
EXPOSE 8080

# 容器启动时执行的命令
CMD ["./cos-proxy"]