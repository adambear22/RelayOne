# NodePass 管理平台

![CI Status](https://img.shields.io/github/actions/workflow/status/<ORG>/nodepass-hub/ci.yml?branch=main) ![Latest Release](https://img.shields.io/github/v/release/<ORG>/nodepass-hub) ![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Go Version](https://img.shields.io/badge/go-1.22%2B-00ADD8) ![Docker Pulls](https://img.shields.io/docker/pulls/<ORG>/nodepass-hub)

## 简介

NodePass 管理平台是基于 NodePass 核心引擎的延伸型前端管理系统，提供企业级的流量转发与管理能力。平台以集中式 Hub + 分布式 Agent 架构为核心，通过 WebSocket 实现实时双向通信，为用户提供节点管理、流量控制、VIP 会员体系和权限管理的一体化解决方案。

平台遵循 API 优先、零配置部署、单一 SSE 通道和渐进式复杂度设计原则：新手可以快速完成常见操作，专家用户可按需展开高级参数，实现从单节点转发到负载均衡、多跳链路的统一运维体验。

## 架构概览

以下为开发手册 §1.3 的系统边界图：

```text
┌─────────────────────────────────────────────────────────┐
│                      外部系统                            │
│  Telegram Bot API │ 外部计费系统 │ 第三方集成            │
└──────────┬──────────────┬──────────────┬────────────────┘
           │              │              │
┌──────────▼──────────────▼──────────────▼────────────────┐
│                   NodePass 管理平台                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Web 前端   │  │   REST API   │  │  WebSocket Hub │  │
│  │  (用户界面) │  │  (业务逻辑)  │  │  (节点通信)    │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         │ SSE(单一全局流) │                  │            │
│  ┌──────▼────────────────▼──────────────────▼────────┐  │
│  │              PostgreSQL 数据层                      │  │
│  └─────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │ WebSocket / NodePass Protocol
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Agent A    │ │  Agent B    │ │  Agent C    │
    │ ┌─────────┐ │ │ ┌─────────┐ │ │ ┌─────────┐ │
    │ │NodePass │ │ │ │NodePass │ │ │ │NodePass │ │
    │ │(嵌入式) │ │ │ │(嵌入式) │ │ │ │(嵌入式) │ │
    │ └─────────┘ │ │ └─────────┘ │ │ └─────────┘ │
    └─────────────┘ └─────────────┘ └─────────────┘
```

## 快速开始

### 前置要求

- Docker 20.10+ 与 Docker Compose v2
- 域名（用于 HTTPS 和 Telegram Webhook）

### 一键部署

```bash
curl -fsSL https://raw.githubusercontent.com/<ORG>/nodepass-hub/main/deploy/setup.sh | bash
```

### 手动部署

```bash
git clone https://github.com/<ORG>/nodepass-hub.git
cd nodepass-hub
cp deploy/.env.example deploy/.env
# 编辑 deploy/.env

docker compose up -d
```

## 开发环境

```bash
git clone https://github.com/<ORG>/nodepass-hub.git
cd nodepass-hub
make dev-up
```

访问 [http://localhost:5173](http://localhost:5173)。

## 文档

- [开发手册](docs/DEVELOPMENT.md)
- [API 文档](docs/API.md)
- [部署指南](deploy/README.md)
- [Agent 接入](nodepass-agent/README.md)

## License

MIT
