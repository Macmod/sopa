package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	adws "github.com/Macmod/sopa"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type customCreateTemplate struct {
	ParentDN  string                  `yaml:"parentDN"`
	RDN       string                  `yaml:"rdn"`
	Attrs     []customCreateAttribute `yaml:"attributes"`
	Comment   string                  `yaml:"comment"`
	ObjectDN  string                  `yaml:"dn"` // optional (informational)
	SchemaVer string                  `yaml:"schema"`
}

type customCreateAttribute struct {
	Name   string   `yaml:"name"`
	Type   string   `yaml:"type"`
	Value  *string  `yaml:"value"`
	Values []string `yaml:"values"`
}

func newCreateCustomCmd(common *commonOptions) *cobra.Command {
	var templatePath string

	cmd := &cobra.Command{
		Use:   "custom --template <file.yaml>",
		Short: "Create a custom object from a YAML template",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)

			templatePath = strings.TrimSpace(templatePath)
			if templatePath == "" {
				return fmt.Errorf("--template is required")
			}

			tpl, attrs, err := loadCustomCreateTemplate(templatePath)
			if err != nil {
				return err
			}

			newDN := fmt.Sprintf("%s,%s", tpl.RDN, tpl.ParentDN)
			p.Infof("Creating custom object: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferCreateCustom(tpl.ParentDN, tpl.RDN, attrs)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&templatePath, "template", "", "YAML template file path")
	_ = cmd.MarkFlagRequired("template")
	return cmd
}

func loadCustomCreateTemplate(path string) (*customCreateTemplate, []adws.IMDAAttribute, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read template: %w", err)
	}

	var tpl customCreateTemplate
	// PowerShell's Set-Content -Encoding UTF8 can write a UTF-8 BOM. yaml.v3 can choke on it,
	// so strip it if present.
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	if err := yaml.Unmarshal(b, &tpl); err != nil {
		return nil, nil, fmt.Errorf("parse template YAML: %w", err)
	}

	tpl.ParentDN = strings.TrimSpace(tpl.ParentDN)
	tpl.RDN = strings.TrimSpace(tpl.RDN)
	if tpl.ParentDN == "" {
		return nil, nil, fmt.Errorf("template parentDN is required")
	}
	if tpl.RDN == "" {
		return nil, nil, fmt.Errorf("template rdn is required")
	}
	if len(tpl.Attrs) == 0 {
		return nil, nil, fmt.Errorf("template attributes is required")
	}

	attrs := make([]adws.IMDAAttribute, 0, len(tpl.Attrs))
	for i := 0; i < len(tpl.Attrs); i++ {
		a := tpl.Attrs[i]
		name := strings.TrimSpace(a.Name)
		if name == "" {
			return nil, nil, fmt.Errorf("template attributes[%d].name is required", i)
		}

		// Prevent users from setting these; they are always injected by the builder.
		if strings.EqualFold(name, "ad:relativeDistinguishedName") || strings.EqualFold(name, "ad:container-hierarchy-parent") {
			return nil, nil, fmt.Errorf("template attributes[%d].name %q is not allowed (auto-set)", i, name)
		}

		attrType, err := normalizeIMDAAttributeType(name)
		if err != nil {
			return nil, nil, fmt.Errorf("template attributes[%d].name: %w", i, err)
		}

		vals, err := normalizeTemplateValues(a)
		if err != nil {
			return nil, nil, fmt.Errorf("template attributes[%d] values: %w", i, err)
		}

		xsiType, converted, err := convertTemplateTypeAndValues(a.Type, vals)
		if err != nil {
			return nil, nil, fmt.Errorf("template attributes[%d].type: %w", i, err)
		}

		attrs = append(attrs, adws.IMDAAttribute{Name: attrType, XSIType: xsiType, Values: converted})
	}

	return &tpl, attrs, nil
}

func normalizeTemplateValues(a customCreateAttribute) ([]string, error) {
	hasValue := a.Value != nil
	hasValues := len(a.Values) > 0
	if hasValue && hasValues {
		return nil, fmt.Errorf("provide either value or values, not both")
	}
	if hasValue {
		return []string{*a.Value}, nil
	}
	if hasValues {
		return a.Values, nil
	}
	return nil, fmt.Errorf("no value(s) provided")
}

func convertTemplateTypeAndValues(typ string, values []string) (xsiType string, out []string, err error) {
	typ = strings.TrimSpace(strings.ToLower(typ))
	if typ == "" {
		typ = "string"
	}

	switch typ {
	case "string", "xsd:string":
		return "xsd:string", values, nil
	case "int", "xsd:int":
		return "xsd:int", values, nil
	case "bool", "boolean", "xsd:boolean":
		return "xsd:boolean", values, nil
	case "base64", "xsd:base64binary":
		out = make([]string, 0, len(values))
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				return "", nil, fmt.Errorf("base64 value cannot be empty")
			}
			// Validate base64.
			if _, decErr := base64.StdEncoding.DecodeString(v); decErr != nil {
				return "", nil, fmt.Errorf("invalid base64: %w", decErr)
			}
			out = append(out, v)
		}
		return "xsd:base64Binary", out, nil
	case "hex":
		out = make([]string, 0, len(values))
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				return "", nil, fmt.Errorf("hex value cannot be empty")
			}
			b, decErr := hex.DecodeString(v)
			if decErr != nil {
				return "", nil, fmt.Errorf("invalid hex: %w", decErr)
			}
			out = append(out, base64.StdEncoding.EncodeToString(b))
		}
		return "xsd:base64Binary", out, nil
	default:
		// Allow passing explicit xsd:* types through.
		if strings.HasPrefix(typ, "xsd:") {
			return typ, values, nil
		}
		return "", nil, fmt.Errorf("unsupported type %q (use string|int|bool|base64|hex or an explicit xsd: type)", typ)
	}
}

func escapeXMLLocalName(name string) string {
	if name == "" {
		return ""
	}
	// Replace spaces and invalid XML characters with underscores
	escaped := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, name)
	return escaped
}

func normalizeIMDAAttributeType(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if strings.Contains(name, ":") {
		return name, nil
	}
	local := escapeXMLLocalName(name)
	if local == "" {
		return "", fmt.Errorf("invalid attribute name %q", name)
	}
	return "addata:" + local, nil
}
