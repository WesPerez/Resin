package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Resinat/Resin/internal/service"
)

type inheritLeaseRequest struct {
	ParentAccount string `json:"parent_account"`
	NewAccount    string `json:"new_account"`
}

// NewTokenActionHandler returns the handler for token-path actions.
func NewTokenActionHandler(proxyToken string, cp *service.ControlPlaneService, apiMaxBodyBytes int64) http.Handler {
	if cp == nil {
		return http.NotFoundHandler()
	}

	mux := http.NewServeMux()
	mux.Handle("POST /{token}/api/v1/{platform}/actions/inherit-lease", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := PathParam(r, "token")
		if proxyToken != "" && token != proxyToken {
			http.NotFound(w, r)
			return
		}

		platformName := strings.TrimSpace(PathParam(r, "platform"))
		if platformName == "" {
			writeInvalidArgument(w, "platform: must be non-empty")
			return
		}

		var req inheritLeaseRequest
		if err := DecodeBody(r, &req); err != nil {
			writeDecodeBodyError(w, err)
			return
		}

		if err := cp.InheritLeaseByPlatformName(platformName, req.ParentAccount, req.NewAccount); err != nil {
			writeServiceError(w, err)
			return
		}

		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	registerRecoveryActions(mux, proxyToken, cp)

	return RequestBodyLimitMiddleware(apiMaxBodyBytes, mux)
}

func registerRecoveryActions(mux *http.ServeMux, proxyToken string, cp *service.ControlPlaneService) {
	for _, action := range []string{"acquire", "report-failure"} {
		mux.HandleFunc("POST /proxy-api/v1/{platform}/leases/{account}/actions/"+action, func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if proxyToken == "" || !strings.HasPrefix(auth, "Bearer ") ||
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(proxyToken)) != 1 {
				http.NotFound(w, r)
				return
			}
			var result *service.RecoveryLeaseResponse
			var err error
			if action == "acquire" {
				var req service.AcquireRecoveryLeaseRequest
				if err = DecodeBody(r, &req); err != nil {
					writeDecodeBodyError(w, err)
					return
				}
				result, err = cp.AcquireRecoveryLease(PathParam(r, "platform"), PathParam(r, "account"), req)
			} else {
				var req service.ReportLeaseFailureRequest
				if err = DecodeBody(r, &req); err != nil {
					writeDecodeBodyError(w, err)
					return
				}
				result, err = cp.ReportLeaseFailure(PathParam(r, "platform"), PathParam(r, "account"), req)
			}
			if err != nil {
				writeServiceError(w, err)
				return
			}
			WriteJSON(w, http.StatusOK, result)
		})
	}
}
