//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestAdminCRUDNode(t *testing.T) {
	adminToken := loginAs(t, getEnv(t).adminUsername, adminPassword)

	node := createNode(t, adminToken)
	if node.ID.String() == "" {
		t.Fatal("expected node id")
	}

	getResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodGet,
		"/api/v1/nodes/"+node.ID.String(),
		nil,
		authHeader(adminToken),
		nil,
	)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected status 200 for get, got %d body=%s", getResp.Code, getResp.Body.String())
	}

	updateResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPut,
		"/api/v1/nodes/"+node.ID.String(),
		map[string]interface{}{
			"name": "updated-node-name",
		},
		authHeader(adminToken),
		nil,
	)
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected status 200 for update, got %d body=%s", updateResp.Code, updateResp.Body.String())
	}

	deleteResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodDelete,
		"/api/v1/nodes/"+node.ID.String(),
		nil,
		authHeader(adminToken),
		nil,
	)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected status 200 for delete, got %d body=%s", deleteResp.Code, deleteResp.Body.String())
	}
}
