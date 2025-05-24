# wg-punch-kernel: WireGuard Punch Kernel Extension 
`wg-punch-kernel` extends [wg-punch](https://github.com/yago-123/wg-punch) to support **kernel-based WireGuard** tunnels
for NAT hole punching in Go.

## Overview
This module provides a `Tunnel` implementation that uses the **WireGuard kernel module** instead of the userspace version.
It is a drop-in replacement for wg-punch’s userspace tunnel, using the kernel WireGuard module for native integration 
with the system networking stack.
- Reuses `wg-punch`’s NAT traversal logic
- Uses kernel WireGuard for real tunnel setup
- Cleanly integrates with your existing Go code
- Tested with peer-to-peer TCP communication over WireGuard

## Use Case
Use this project when:
- You want to establish direct peer-to-peer connections across NATs using WireGuard
- You prefer **kernel WireGuard** (via `wgctrl` and `netlink`) over userspace `wireguard-go`
- You already use or plan to use [wg-punch](https://github.com/yago-123/wg-punch)

## Example
See [`cmd/peerA/main.go`](./cmd/peerA/main.go) and [`cmd/peerB/main.go`](./cmd/peerB/main.go) for a minimal example of establishing a tunnel between two peers using NAT hole punching and kernel WireGuard.

## Requirements
- Linux with WireGuard kernel module installed
- Go 1.20+

## Installation
```bash
go get github.com/yago-123/wg-punch-kernel
```