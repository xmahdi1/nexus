package crypto

import (
	"bytes"
	"testing"
)

func TestTemplateEncryptionPreservesDefinitionAndBindsIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	input := TemplateDefinition{Compose: "services: {} # fixture private source", VarsJSON: `[{"name":"PASSWORD","default":"private-fixture"}]`, PostDeploy: "fixture private instructions"}
	one, err := EncryptTemplateDefinition(key, "one", input)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EncryptTemplateDefinition(key, "one", input)
	if err != nil || one == two {
		t.Fatal("nonce not random", err)
	}
	result, err := DecryptTemplateDefinition(key, "one", one)
	if err != nil || result != input {
		t.Fatal("definition changed", err)
	}
	if _, err := DecryptTemplateDefinition(key, "two", one); err == nil {
		t.Fatal("swapped definition accepted")
	}
	if _, err := DecryptTemplateDefinition(bytes.Repeat([]byte{4}, 32), "one", one); err == nil {
		t.Fatal("wrong key accepted")
	}
}
