package value

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// MaxYAMLBytes bounds configuration and fixture files.
const MaxYAMLBytes = 4 << 20

// DecodeYAMLStrict decodes exactly one YAML document into v with known-field
// checking: unknown fields and duplicate keys are errors (ERR_CONFIG).
func DecodeYAMLStrict(data []byte, v any) error {
	if len(data) > MaxYAMLBytes {
		return fmt.Errorf("%w: YAML document of %d bytes exceeds %d", ErrConfig, len(data), MaxYAMLBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: more than one YAML document", ErrConfig)
	}
	return nil
}
