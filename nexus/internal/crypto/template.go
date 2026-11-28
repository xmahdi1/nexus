package crypto

import (
	"encoding/json"
	"errors"
	"strings"
)

type TemplateDefinition struct {
	Compose    string `json:"compose"`
	VarsJSON   string `json:"varsJson"`
	PostDeploy string `json:"postDeploy"`
}

func templateBinding(id string) []byte { return []byte("nexus:template-definition:v1\x00" + id) }
func EncryptTemplateDefinition(key []byte, id string, value TemplateDefinition) (string, error) {
	if len(key) != 32 || id == "" || strings.ContainsRune(id, 0) {
		return "", errors.New("invalid template encryption context")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	defer clear(data)
	sealed, err := EncryptBound(key, data, templateBinding(id))
	if err != nil {
		return "", err
	}
	return "v1:" + sealed, nil
}
func DecryptTemplateDefinition(key []byte, id, value string) (TemplateDefinition, error) {
	var result TemplateDefinition
	if len(key) != 32 || id == "" || strings.ContainsRune(id, 0) || !strings.HasPrefix(value, "v1:") {
		return result, errors.New("invalid template encryption context")
	}
	data, err := DecryptBound(key, strings.TrimPrefix(value, "v1:"), templateBinding(id))
	if err != nil {
		return result, err
	}
	defer clear(data)
	if err := json.Unmarshal(data, &result); err != nil {
		return TemplateDefinition{}, errors.New("invalid encrypted template definition")
	}
	return result, nil
}
