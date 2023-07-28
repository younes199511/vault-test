package main

import (
	"io/ioutil"
	"os"
	"testing"

	vaultKv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	vaultCert "github.com/hashicorp/vault/builtin/credential/cert"
	vaultPki "github.com/hashicorp/vault/builtin/logical/pki"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	vaultCore "github.com/hashicorp/vault/vault"
)

const (
	correctPasswordForTest string = "secretPasswordOfTest"
	PolicyName             string = "kv-policy"
	KvPolicy               string = `
	path "auth/token/create" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
	}
	path "*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
	}
	path "kv/*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
	}
	path "kv/data/*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
	}
	path "kv/metadata/external/*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]	
	}
	path "kv/metadata/internal/*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]	
	}
	path "kv/internal/bad" {
		capabilities = ["deny"]
	}
	path "sys/tools/random" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "sys/tools/random/*" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "/auth/token/lookup-self" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "/auth/token/renew-self" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "/transit/" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}	
`
)

func CreateVaultTest(t *testing.T, newPolicy, newPolicyName string) *vaultCore.TestCluster {
	t.Helper()

	coreConfig := &vaultCore.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultCert.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"kv":  vaultKv.Factory,
			"pki": vaultPki.Factory,
		},
	}
	cluster := vaultCore.NewTestCluster(t, coreConfig, &vaultCore.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	authOptions := &api.EnableAuthOptions{
		Type: "cert",
	}

	sys := cluster.Cores[0].Client.Sys()
	err := sys.EnableAuthWithOptions("cert", authOptions)
	if err != nil {
		t.Fatal("failed creating cert backend options")
	}

	// Create KV V2 mount
	kvMount := api.MountInput{}
	kvMount.Type = "kv-v2"

	sys.Mount("kv/", &kvMount)

	err = sys.PutPolicy(PolicyName, KvPolicy)
	if err != nil {
		t.Fatal("could not create policy")
	}

	var tokenPolicies []string
	if newPolicy != "" && newPolicyName != "" {
		sys.PutPolicy(newPolicyName, newPolicy)
		tokenPolicies = []string{PolicyName, newPolicyName}
	} else {
		tokenPolicies = []string{PolicyName}
	}

	// Setup required secrets, policies, etc.
	_, err = cluster.Cores[0].Client.Logical().Write("kv/data/foo", map[string]interface{}{
		"secret": "bar",
	})

	body := make(map[string]interface{})
	body["password"] = correctPasswordForTest
	// Let us set up a fake password to test the Check and the Reset APIs.
	_, err = cluster.Cores[0].Client.Logical().Write("kv/data/external/Test/password", map[string]interface{}{
		"data": body,
	})
	if err != nil {
		t.Fatal("failed creating auth cert backend: ", err)
	}
	_, err = cluster.Cores[0].Client.Logical().Write("auth/cert/certs/test", map[string]interface{}{
		"certificate":    string(cluster.CACertPEM),
		"token_period":   0, // period of 0 means token never expires
		"token_policies": tokenPolicies,
	})

	if err != nil {
		t.Fatal("failed creating auth cert backend: ", err)
	}

	createTestDirectoriesAndStoreCerts(t, cluster)

	return cluster
}

func createTestDirectoriesAndStoreCerts(t *testing.T, cluser *vaultCore.TestCluster) {
	t.Helper()

	os.RemoveAll("/app/.edge")

	err := os.MkdirAll("/app/.edge", os.ModeDir)
	if err != nil {
		t.Fatal("could not create edge directory...\n", err)
	}

	err = os.Mkdir("/app/.edge/ca", os.ModeDir)
	if err != nil {
		t.Fatal("could not create ca directory...\n", err)
	}

	err = os.Mkdir("/app/.edge/test1", os.ModeDir)
	if err != nil {
		t.Fatal("could not create test1 directory...\n", err)
	}

	err = ioutil.WriteFile("/app/.edge/ca/ca.pem", cluser.CACertPEM, 0644)
	if err != nil {
		t.Fatal("could not store ca...\n", err)
	}

	err = ioutil.WriteFile("/app/.edge/test1/test1.pem", cluser.Cores[0].ServerCertPEM, 0644)
	if err != nil {
		t.Fatal("could not store cert...\n", err)
	}

	err = ioutil.WriteFile("/app/.edge/test1/test1.pk", cluser.Cores[0].ServerKeyPEM, 0644)
	if err != nil {
		t.Fatal("could not store key...\n", err)
	}
}

func TestNewVaultClient(t *testing.T) {
	tagPolicyName := "tag-policy"
	tagPolicy := `
	path "auth/token/create" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
	}
	path "kv/*" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "sys/tools/random" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "sys/tools/random/*" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "/auth/token/lookup-self" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	path "/auth/token/renew-self" {
		capabilities = ["create", "read", "update", "delete", "list"]
	}
	`
	cluster := CreateVaultTest(t, tagPolicy, tagPolicyName)
	defer cluster.Cleanup()
}
