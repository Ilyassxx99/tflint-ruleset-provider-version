package main

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/logger"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// Helper function to format hclext.BodyContent for clear text logging
func formatBodyContent(body *hclext.BodyContent) string {
	if body == nil {
		return "nil"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Attributes: %v\n", body.Attributes))
	sb.WriteString("Blocks: [\n")
	for _, block := range body.Blocks {
		sb.WriteString(formatBlock(block))
	}
	sb.WriteString("]")
	return sb.String()
}

// Helper function to format hclext.Block for clear text logging
func formatBlock(block *hclext.Block) string {
	if block == nil {
		return "  nil\n"
	}
	return fmt.Sprintf("  {Type: %s, Labels: %v, Attributes: %v, DefRange: %s}\n",
		block.Type, block.Labels, block.Body.Attributes, block.DefRange)
}

type ProviderVersionRule struct {
	tflint.DefaultRule
}

func NewProviderVersionRule() *ProviderVersionRule {
	return &ProviderVersionRule{}
}

func (r *ProviderVersionRule) Name() string {
	return "provider_version_check"
}

func (r *ProviderVersionRule) Enabled() bool {
	return true
}

func (r *ProviderVersionRule) Severity() tflint.Severity {
	return tflint.ERROR
}

func (r *ProviderVersionRule) Link() string {
	return "https://example.com/provider-version-check"
}

func (r *ProviderVersionRule) Check(runner tflint.Runner) error {
	logger.Info("Starting provider_version_check rule")

	// Approved provider versions
	approvedVersions := map[string][2]string{
		"hashicorp/aws":     {"4.0", "5.0"},
		"hashicorp/azurerm": {"3.0", "4.0"},
		"hashicorp/google":  {"4.0", "5.0"},
		"hashicorp/azure":   {"3.0", "4.0"},
	}

	// Define schema for required_providers block
	body, err := runner.GetModuleContent(&hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "terraform",
				Body: &hclext.BodySchema{
					Blocks: []hclext.BlockSchema{
						{
							Type:       "required_providers",
							LabelNames: []string{},
							Body: &hclext.BodySchema{
								Attributes: []hclext.AttributeSchema{
									{Name: "aws"},
									{Name: "azure"},
									// Add more provider names if needed
								},
							},
						},
					},
				},
			},
		},
	}, &tflint.GetModuleContentOption{
		ModuleCtx:  tflint.SelfModuleCtxType,
		ExpandMode: tflint.ExpandModeExpand,
	})
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get module content: %s", err))
		return err
	}
	logger.Info(fmt.Sprintf("BodyContent: %s", formatBodyContent(body)))

	// Check provider versions
	for _, block := range body.Blocks {
		logger.Info(fmt.Sprintf("Body Block: %s", formatBlock(block)))
		if block.Type == "terraform" {
			for _, reqProviders := range block.Body.Blocks {
				logger.Info(fmt.Sprintf("Req Provider: %s", formatBlock(reqProviders)))
				if reqProviders.Type == "required_providers" {
					logger.Info(fmt.Sprintf("Provider Attributes: %v", reqProviders.Body.Attributes))
					for providerName, attrValue := range reqProviders.Body.Attributes {
						exprValue, diags := attrValue.Expr.Value(nil)
						if diags.HasErrors() {
							logger.Error(fmt.Sprintf("Failed to evaluate %s: %s", providerName, diags))
							return fmt.Errorf("failed to evaluate %s: %s", providerName, diags)
						}
						if !exprValue.Type().IsObjectType() {
							logger.Warn(fmt.Sprintf("Invalid provider %s: must be an object", providerName))
							runner.EmitIssue(
								r,
								fmt.Sprintf("Invalid provider %s: must be an object", providerName),
								attrValue.Range,
							)
							continue
						}
						providerObj := exprValue.AsValueMap()
						source := providerObj["source"].AsString()
						versionStr := providerObj["version"].AsString()
						logger.Info(fmt.Sprintf("Provider: %s, Source: %s, Version: %s", providerName, source, versionStr))
						if versionRange, ok := approvedVersions[source]; ok {
							// Clean version string (remove ~>, >=, etc.)
							cleanedVersion := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(versionStr, "~>"), ">="))
							v, err := version.NewVersion(cleanedVersion)
							if err != nil {
								logger.Warn(fmt.Sprintf("Invalid version format for %s: %s", source, versionStr))
								runner.EmitIssue(
									r,
									fmt.Sprintf("Invalid version format for %s: %s", source, versionStr),
									attrValue.Range,
								)
								continue
							}
							minV, err := version.NewVersion(versionRange[0])
							if err != nil {
								logger.Error(fmt.Sprintf("Invalid min version %s: %s", versionRange[0], err))
								return fmt.Errorf("invalid min version %s: %s", versionRange[0], err)
							}
							maxV, err := version.NewVersion(versionRange[1])
							if err != nil {
								logger.Error(fmt.Sprintf("Invalid max version %s: %s", versionRange[1], err))
								return fmt.Errorf("invalid max version %s: %s", versionRange[1], err)
							}
							if !(v.GreaterThanOrEqual(minV) && v.LessThan(maxV)) {
								logger.Warn(fmt.Sprintf("Non-compliant version for %s: got %s, expected %s-%s", source, versionStr, versionRange[0], versionRange[1]))
								runner.EmitIssue(
									r,
									fmt.Sprintf("Non-compliant version for %s: got %s, expected %s-%s", source, versionStr, versionRange[0], versionRange[1]),
									attrValue.Range,
								)
							}
						}
					}
				}
			}
		}
	}
	logger.Info("Completed provider_version_check rule")
	return nil
}
