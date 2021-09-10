package mux

import (
	"net"
	"net/http"
	"strings"

	krakendrate "github.com/badboyd/krakend-ratelimit"
	"github.com/luraproject/lura/config"
	"github.com/luraproject/lura/proxy"
	krakendmux "github.com/luraproject/lura/router/mux"

	"github.com/badboyd/krakend-ratelimit/juju"
	"github.com/badboyd/krakend-ratelimit/juju/router"
)

var HandlerFactory = NewRateLimiterMw(krakendmux.EndpointHandler)

// NewRateLimiterMw builds a rate limiting wrapper over the received handler factory.
func NewRateLimiterMw(next krakendmux.HandlerFactory) krakendmux.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) http.HandlerFunc {
		handlerFunc := next(remote, p)

		cfg := router.ConfigGetter(remote.ExtraConfig).(router.Config)
		if cfg == router.ZeroCfg || (cfg.MaxRate <= 0 && cfg.ClientMaxRate <= 0) {
			return handlerFunc
		}

		if cfg.MaxRate > 0 {
			handlerFunc = NewEndpointRateLimiterMw(juju.NewLimiter(float64(cfg.MaxRate), cfg.MaxRate))(handlerFunc)
		}

		if cfg.ClientMaxRate > 0 {
			switch strings.ToLower(cfg.Strategy) {
			case "ip":
				handlerFunc = NewIpLimiterMwWithKey(cfg.Key, float64(cfg.ClientMaxRate), cfg.ClientMaxRate)(handlerFunc)
			case "header":
				handlerFunc = NewHeaderLimiterMw(cfg.Key, float64(cfg.ClientMaxRate), cfg.ClientMaxRate)(handlerFunc)
			}
		}
		return handlerFunc
	}
}

// EndpointMw is a function that decorates the received handlerFunc with some rateliming logic
type EndpointMw func(http.HandlerFunc) http.HandlerFunc

// NewEndpointRateLimiterMw creates a simple ratelimiter for a given handlerFunc
func NewEndpointRateLimiterMw(tb juju.Limiter) EndpointMw {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !tb.Allow() {
				http.Error(w, krakendrate.ErrLimited.Error(), http.StatusServiceUnavailable)
				return
			}
			next(w, r)
		}
	}
}

// NewHeaderLimiterMw creates a token ratelimiter using the value of a header as a token
func NewHeaderLimiterMw(header string, maxRate float64, capacity int64) EndpointMw {
	return NewTokenLimiterMw(HeaderTokenExtractor(header), juju.NewMemoryStore(maxRate, capacity))
}

// NewHeaderLimiterMw creates a token ratelimiter using the IP of the request as a token
func NewIpLimiterMwWithKey(header string, maxRate float64, capacity int64) EndpointMw {
	return NewTokenLimiterMw(NewIPTokenExtractor(header), juju.NewMemoryStore(maxRate, capacity))
}

//TokenExtractor defines the interface of the functions to use in order to extract a token for each request
type TokenExtractor func(http.ResponseWriter, *http.Request) string

// IPTokenExtractor extracts the IP of the request
func IPTokenExtractor(c http.ResponseWriter, r *http.Request) string {
	return r.RemoteAddr
}

// NewIPTokenExtractor generates an IP TokenExtractor checking first for the contents of the passed header.
// If nothing is found there, the regular IPTokenExtractor function is called.
func NewIPTokenExtractor(header string) TokenExtractor {
	return func(w http.ResponseWriter, r *http.Request) string {
		if clientIP := strings.TrimSpace(strings.Split(r.Header.Get(header), ",")[0]); clientIP != "" {
			ip := strings.Split(clientIP, ":")[0]
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
		return IPTokenExtractor(w, r)
	}
}

// HeaderTokenExtractor returns a TokenExtractor that looks for the value of the designed header
func HeaderTokenExtractor(header string) TokenExtractor {
	return func(w http.ResponseWriter, r *http.Request) string { return r.Header.Get(header) }
}

// NewTokenLimiterMw returns a token based ratelimiting endpoint middleware with the received TokenExtractor and LimiterStore
func NewTokenLimiterMw(tokenExtractor TokenExtractor, limiterStore krakendrate.LimiterStore) EndpointMw {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tokenKey := tokenExtractor(w, r)
			if tokenKey == "" {
				http.Error(w, krakendrate.ErrLimited.Error(), http.StatusTooManyRequests)
				return
			}

			if !limiterStore(tokenKey).Allow() {
				http.Error(w, krakendrate.ErrLimited.Error(), http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}
}
