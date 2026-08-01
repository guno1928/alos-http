//go:build !linux

package core

// Platforms without the epoll data path forward through the blocking std-net
// path, which takes its upstream connections from the per-backend pool.
const backendPoolRequired = true
