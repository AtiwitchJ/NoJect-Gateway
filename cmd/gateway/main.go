package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"noject/internal/audit"
	"noject/internal/auth"
	"noject/internal/config"
	"noject/internal/dashboard"
	"noject/internal/guardclient"
	"noject/internal/metrics"
	"noject/internal/router"
	"noject/internal/waf"
)

const (
	Version = "1.0.0"
	Banner  = `
  _   _         _           _   
 | \ | |       | |         | |  
 |  \| | ___   | | ___  ___| |_ 
 | . ` + "`" + ` |/ _ \  | |/ _ \/ __| __|
 | |\  | (_) |_| |  __/ (__| |_ 
 |_| \_|\___/\__/ \___|\___|\__|
 Universal AI & Security API Gateway (ISO 27001 / ISO 42001)
`
)

// requireAuth wraps an operator-facing handler so it is reachable only with
// valid credentials. These endpoints serve security telemetry (client IPs,
// blocked-request reasons with matched attack samples), which is both PII
// and a live map of what is evading the filters — not public data.
func requireAuth(authenticator auth.Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := authenticator.Authenticate(r); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"authentication required for operator endpoints"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	configPath := flag.String("config", "configs/gateway.yaml", "Path to YAML configuration file")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	verifyAuditPath := flag.String("verify-audit", "", "Verify an audit hash-chain and its latest checkpoint when present")
	flag.Parse()

	if *showVersion {
		fmt.Printf("NoJect Gateway v%s\n", Version)
		os.Exit(0)
	}

	// Tooling mode: Verify audit logs
	if *verifyAuditPath != "" {
		f, err := os.Open(*verifyAuditPath)
		if err != nil {
			log.Fatalf("Error opening audit log: %v", err)
		}
		defer f.Close()

		res, err := audit.VerifyLatestCheckpoint(f)
		if err != nil {
			log.Fatalf("Audit verification error: %v", err)
		}

		if res.Valid {
			fmt.Printf("✅ AUDIT LOG INTEGRITY VERIFIED: All %d records match SHA-256 hash chain.\n", res.TotalRecords)
			os.Exit(0)
		} else {
			fmt.Printf("❌ AUDIT LOG TAMPERING DETECTED at record %d: %s\n", res.BrokenAtIndex, res.Reason)
			os.Exit(1)
		}
	}

	fmt.Print(Banner)
	log.Printf("[INFO] Loading configuration from %s...", *configPath)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
	}

	// 1. Initialize ISO 27001 Audit Logger
	auditLogger, err := audit.NewFileLogger(cfg.Audit.OutputPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize audit logger: %v", err)
	}
	defer auditLogger.Close()
	log.Printf("[INFO] ISO 27001 Audit Logger active (Output: %s, HashChaining: %v)", cfg.Audit.OutputPath, cfg.Audit.HashChaining)

	// 2. Initialize Multi-Auth
	var authOpts []auth.Option
	if cfg.Auth.APIKey.Enabled {
		apiKeyRegistry := auth.NewAPIKeyRegistry()
		for _, k := range cfg.Auth.APIKey.Keys {
			apiKeyRegistry.RegisterKey(k.Key, auth.APIKeyMetadata{
				ID:        k.ID,
				TenantID:  k.TenantID,
				Roles:     k.Roles,
				RateLimit: k.RateLimit,
			})
		}
		authOpts = append(authOpts, auth.WithAPIKeyAuth(apiKeyRegistry, cfg.Auth.APIKey.Header))
		log.Printf("[INFO] API Key Auth enabled (%d keys loaded)", len(cfg.Auth.APIKey.Keys))
	}

	if cfg.Auth.JWT.Enabled {
		jwtAuth := auth.NewJWTAuthenticator(auth.JWTConfig{
			Secret:   []byte(cfg.Auth.JWT.Secret),
			Issuer:   cfg.Auth.JWT.Issuer,
			Audience: cfg.Auth.JWT.Audience,
		})
		authOpts = append(authOpts, auth.WithJWTAuth(jwtAuth))
		log.Printf("[INFO] JWT Auth enabled (Issuer: %s)", cfg.Auth.JWT.Issuer)
	}

	multiAuth := auth.NewMultiAuthenticator(authOpts...)

	// 3. Initialize Fast-Path WAF
	wafEngine := waf.NewEngine(waf.DefaultConfig())
	log.Printf("[INFO] Fast-Path WAF active (SQLi, XSS, CMD, Path Traversal)")

	// 4. Initialize AI Guard Client
	guardClient := guardclient.NewClient(guardclient.Config{
		Endpoint:       cfg.GuardEngine.Endpoint,
		Timeout:        time.Duration(cfg.GuardEngine.TimeoutMS) * time.Millisecond,
		FallbackAction: cfg.GuardEngine.FallbackAction,
		// Shared secret presented to the guard engine; must match the engine's
		// NOJECT_GUARD_SHARED_KEY. When unset and the engine has no key either,
		// auth is a no-op (local development).
		SharedKey: os.Getenv("NOJECT_GUARD_SHARED_KEY"),
	})
	if os.Getenv("NOJECT_GUARD_SHARED_KEY") != "" {
		log.Printf("[INFO] Guard engine shared-key auth: enabled")
	} else {
		log.Printf("[INFO] Guard engine shared-key auth: disabled (set NOJECT_GUARD_SHARED_KEY on both services to enable)")
	}
	log.Printf("[INFO] AI Guard Client connected to %s (Timeout: %dms)", cfg.GuardEngine.Endpoint, cfg.GuardEngine.TimeoutMS)

	// 5. Initialize Route Table and Gateway Handler
	table := router.NewTable(cfg.Routes)
	gatewayHandler := router.NewGatewayHandler(router.HandlerConfig{
		Table:          table,
		Auth:           multiAuth,
		WAFEngine:      wafEngine,
		GuardClient:    guardClient,
		AuditLogger:    auditLogger,
		MaxBodyBytes:   cfg.Server.MaxBodyBytes,
		TrustedProxies: cfg.Server.TrustedProxies,
	})

	// 6. Setup Multiplexer with Health Checks, Metrics, and Dashboard
	dashHandler := dashboard.NewHandler(metrics.Default())

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","version":"` + Version + `"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	// The dashboard/stats/metrics surfaces expose client IPs and details of
	// blocked requests (including matched attack samples), so they are
	// authenticated by default. Opt out only behind network-level controls.
	adminHandler := http.Handler(dashHandler)
	if cfg.Dashboard.IsAuthRequired() {
		adminHandler = requireAuth(multiAuth, dashHandler)
		log.Printf("[INFO] 🔒 Dashboard and metrics endpoints require authentication")
	} else {
		log.Printf("[WARN] ⚠️  Dashboard and metrics endpoints are UNAUTHENTICATED (dashboard.auth_required=false) — restrict access at the network layer")
	}

	mux.Handle("/dashboard", adminHandler)
	mux.Handle("/dashboard/", adminHandler)
	mux.Handle("/api/stats", adminHandler)
	mux.Handle("/metrics", adminHandler)
	mux.Handle("/", gatewayHandler)

	log.Printf("[INFO] 📊 Web Dashboard live at http://%s:%d/dashboard", cfg.Server.Host, cfg.Server.Port)
	log.Printf("[INFO] 📈 Prometheus Metrics live at http://%s:%d/metrics", cfg.Server.Host, cfg.Server.Port)

	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 7. Graceful Shutdown listener
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INFO] 🚀 NoJect Gateway listening on %s", serverAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("[INFO] Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Server shutdown error: %v", err)
	}

	log.Println("[INFO] NoJect Gateway stopped successfully.")
}
