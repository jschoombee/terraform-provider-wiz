package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"wiz.io/hashicorp/terraform-provider-wiz/internal/utils"
	"wiz.io/hashicorp/terraform-provider-wiz/internal/wiz"
)

const (
	TestScanPolicyID1 = "fd7dd0c6-4953-4b36-bc39-004ec3d870db"
	TestScanPolicyID2 = "063fb380-9eda-4c08-a31b-9211ee37bd42"
)

func TestHandleIACParams(t *testing.T) {
	ctx := context.Background()

	expected := map[string]interface{}{
		"count_threshold":             3,
		"builtin_ignore_tags_enabled": false,
		"severity_threshold":          "CRITICAL",
		"ignored_rules": []interface{}{
			TestScanPolicyID1,
			TestScanPolicyID2,
		},
		"security_frameworks": []interface{}{
			TestScanPolicyID1,
			TestScanPolicyID2,
		},
		"custom_ignore_tags": []interface{}{
			map[string]interface{}{
				"ignore_all_rules": true,
				"key":              "example_key",
				"value":            "example_value",
				"rule_ids": []interface{}{
					"rule1",
					"rule2",
				},
			},
		},
	}

	input := &wiz.CICDScanPolicyParamsIAC{
		BuiltinIgnoreTagsEnabled: false,
		CountThreshold:           3,
		SeverityThreshold:        "CRITICAL",
		IgnoredRules: []*wiz.CloudConfigurationRule{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
		SecurityFrameworks: []*wiz.SecurityFramework{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
		CustomIgnoreTags: []*wiz.CICDPolicyCustomIgnoreTag{
			{
				IgnoreAllRules: true,
				Key:            "example_key",
				Value:          "example_value",
				Rules: []*wiz.CloudConfigurationRule{
					{
						ID: "rule1",
					},
					{
						ID: "rule2",
					},
				},
			},
		},
	}

	params := handleIACParams(ctx, input)

	if !reflect.DeepEqual(params, expected) {
		t.Fatalf("Expected %v, but got %v", expected, params)
	}
}

func TestFlattenScanPolicyParamsIACNoTags(t *testing.T) {
	ctx := context.Background()
	expected := []interface{}{
		map[string]interface{}{
			"builtin_ignore_tags_enabled": false,
			"count_threshold":             3,
			"custom_ignore_tags":          []interface{}{},
			"ignored_rules": []interface{}{
				TestScanPolicyID1,
				TestScanPolicyID2,
			},
			"security_frameworks": []interface{}{
				TestScanPolicyID1,
				TestScanPolicyID2,
			},
			"severity_threshold": "CRITICAL",
		},
	}
	var expanded = &wiz.CICDScanPolicyParamsIAC{
		BuiltinIgnoreTagsEnabled: false,
		CountThreshold:           3,
		SeverityThreshold:        "CRITICAL",
		IgnoredRules: []*wiz.CloudConfigurationRule{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
		SecurityFrameworks: []*wiz.SecurityFramework{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
	}
	scanPolicyParamsIAC := flattenScanPolicyParams(ctx, "CICDScanPolicyParamsIAC", expanded)
	if !reflect.DeepEqual(scanPolicyParamsIAC, expected) {
		t.Fatalf(
			expectedTestError,
			scanPolicyParamsIAC,
			expected,
		)
	}
}

func TestFlattenScanPolicyParamsIACTags(t *testing.T) {
	ctx := context.Background()
	expected := []interface{}{
		map[string]interface{}{
			"builtin_ignore_tags_enabled": false,
			"count_threshold":             3,
			"custom_ignore_tags": []interface{}{
				map[string]interface{}{
					"ignore_all_rules": false,
					"key":              "testkey1",
					"rule_ids": []interface{}{
						TestScanPolicyID2,
					},
					"value": "testval1",
				},
				map[string]interface{}{
					"ignore_all_rules": false,
					"key":              "testkey2",
					"rule_ids": []interface{}{
						"1f0ee3b5-5404-4b40-bbc8-33a990330ac3",
						"a1958aa1-b810-4df6-bd82-487cb37c6039",
					},
					"value": "testval2",
				},
				map[string]interface{}{
					"ignore_all_rules": true,
					"key":              "testkey3",
					"value":            "testval3",
					"rule_ids":         []interface{}{},
				},
			},
			"ignored_rules": []interface{}{
				TestScanPolicyID1,
				TestScanPolicyID2,
			},
			"security_frameworks": []interface{}{
				TestScanPolicyID1,
				TestScanPolicyID2,
			},
			"severity_threshold": "CRITICAL",
		},
	}
	var expanded = &wiz.CICDScanPolicyParamsIAC{
		BuiltinIgnoreTagsEnabled: false,
		CountThreshold:           3,
		SeverityThreshold:        "CRITICAL",
		IgnoredRules: []*wiz.CloudConfigurationRule{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
		SecurityFrameworks: []*wiz.SecurityFramework{
			{
				ID: TestScanPolicyID1,
			},
			{
				ID: TestScanPolicyID2,
			},
		},
		CustomIgnoreTags: []*wiz.CICDPolicyCustomIgnoreTag{
			{
				IgnoreAllRules: false,
				Key:            "testkey1",
				Value:          "testval1",
				Rules: []*wiz.CloudConfigurationRule{
					{
						ID: TestScanPolicyID2,
					},
				},
			},
			{
				IgnoreAllRules: false,
				Key:            "testkey2",
				Value:          "testval2",
				Rules: []*wiz.CloudConfigurationRule{
					{
						ID: "1f0ee3b5-5404-4b40-bbc8-33a990330ac3",
					},
					{
						ID: "a1958aa1-b810-4df6-bd82-487cb37c6039",
					},
				},
			},
			{
				IgnoreAllRules: true,
				Key:            "testkey3",
				Value:          "testval3",
			},
		},
	}
	scanPolicyParamsIAC := flattenScanPolicyParams(ctx, "CICDScanPolicyParamsIAC", expanded)
	if !reflect.DeepEqual(scanPolicyParamsIAC, expected) {
		t.Fatalf(
			expectedTestError,
			scanPolicyParamsIAC,
			expected,
		)
	}
}

func TestFlattenScanPolicyParamsSecrets(t *testing.T) {
	ctx := context.Background()
	expected := []interface{}{
		map[string]interface{}{
			"count_threshold": 3,
			"path_allow_list": []interface{}{
				"/root",
				"/etc",
			},
		},
	}
	var expanded = &wiz.CICDScanPolicyParamsSecrets{
		CountThreshold: 3,
		PathAllowList: []string{
			"/root",
			"/etc",
		},
	}
	scanPolicyParamsSecrets := flattenScanPolicyParams(ctx, "CICDScanPolicyParamsSecrets", expanded)
	if !reflect.DeepEqual(scanPolicyParamsSecrets, expected) {
		t.Fatalf(
			expectedTestError,
			scanPolicyParamsSecrets,
			expected,
		)
	}
}

func TestFlattenScanPolicyParamsVulnerabilitiesTrue(t *testing.T) {
	ctx := context.Background()
	expected := []interface{}{
		map[string]interface{}{
			"ignore_unfixed": true,
			"package_allow_list": []interface{}{
				"lsof",
				"tcpdump",
			},
			"package_count_threshold": 1,
			"severity":                "HIGH",
		},
	}
	var expanded = &wiz.CICDScanPolicyParamsVulnerabilities{
		IgnoreUnfixed: true,
		PackageAllowList: []string{
			"lsof",
			"tcpdump",
		},
		PackageCountThreshold: 1,
		Severity:              "HIGH",
	}
	scanPolicyParamsVulnerabilities := flattenScanPolicyParams(ctx, "CICDScanPolicyParamsVulnerabilities", expanded)
	if !reflect.DeepEqual(scanPolicyParamsVulnerabilities, expected) {
		t.Fatalf(
			expectedTestError,
			scanPolicyParamsVulnerabilities,
			expected,
		)
	}
}

func TestFlattenScanPolicyParamsVulnerabilitiesFalse(t *testing.T) {
	ctx := context.Background()
	expected := []interface{}{
		map[string]interface{}{
			"ignore_unfixed": false,
			"package_allow_list": []interface{}{
				"lsof",
				"tcpdump",
			},
			"package_count_threshold": 1,
			"severity":                "HIGH",
		},
	}
	var expanded = &wiz.CICDScanPolicyParamsVulnerabilities{
		IgnoreUnfixed: false,
		PackageAllowList: []string{
			"lsof",
			"tcpdump",
		},
		PackageCountThreshold: 1,
		Severity:              "HIGH",
	}
	scanPolicyParamsVulnerabilities := flattenScanPolicyParams(ctx, "CICDScanPolicyParamsVulnerabilities", expanded)
	if !reflect.DeepEqual(scanPolicyParamsVulnerabilities, expected) {
		t.Fatalf(
			expectedTestError,
			scanPolicyParamsVulnerabilities,
			expected,
		)
	}
}

func TestGetDiskVulnerabilitiesParams(t *testing.T) {
	ctx := context.Background()

	var expected = &wiz.CreateCICDScanPolicyDiskVulnerabilitiesInput{
		Severity:              "1525fe10-2575-43ef-84bc-6969f81625e7",
		PackageCountThreshold: 3,
		IgnoreUnfixed:         false,
		PackageAllowList: []string{
			"f9de6434-38bc-4da7-b6ea-ff02ad55073f",
			"675a4ecc-71cb-444a-920e-582b06bbadcb",
		},
	}

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "5fdb33cc-5b36-46ee-9d71-b7282d06271a",
			"disk_vulnerabilities_params": []interface{}{
				map[string]interface{}{
					"severity":                "1525fe10-2575-43ef-84bc-6969f81625e7",
					"package_count_threshold": 3,
					"ignore_unfixed":          false,
					"package_allow_list": []interface{}{
						"f9de6434-38bc-4da7-b6ea-ff02ad55073f",
						"675a4ecc-71cb-444a-920e-582b06bbadcb",
					},
				},
			},
		},
	)

	cicdParams := getDiskVulnerabilitiesParams(ctx, d)

	if !reflect.DeepEqual(expected, cicdParams) {
		t.Fatalf(
			expectedTestError,
			cicdParams,
			expected,
		)
	}
}

func TestGetDiskSecretsParams(t *testing.T) {
	ctx := context.Background()

	var expected = &wiz.CreateCICDScanPolicyDiskSecretsInput{
		CountThreshold: 3,
		PathAllowList: []string{
			"f9de6434-38bc-4da7-b6ea-ff02ad55073f",
			"675a4ecc-71cb-444a-920e-582b06bbadcb",
		},
	}

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "5fdb33cc-5b36-46ee-9d71-b7282d06271a",
			"disk_secrets_params": []interface{}{
				map[string]interface{}{
					"count_threshold": 3,
					"path_allow_list": []interface{}{
						"f9de6434-38bc-4da7-b6ea-ff02ad55073f",
						"675a4ecc-71cb-444a-920e-582b06bbadcb",
					},
				},
			},
		},
	)

	cicdParams := getDiskSecretsParams(ctx, d)

	if !reflect.DeepEqual(expected, cicdParams) {
		t.Fatalf(
			expectedTestError,
			cicdParams,
			expected,
		)
	}
}

func TestGetIACParams(t *testing.T) {
	ctx := context.Background()

	var expected = &wiz.CreateCICDScanPolicyIACInput{
		SeverityThreshold: "5f45a8d4-24b2-463d-b604-ca532e4ec4d3",
		CountThreshold:    3,
		IgnoredRules: []string{
			"1c1e4a07-8062-4c40-849f-b41417887768",
			"3f25530e-3295-462e-a300-4ef456291263",
		},
		BuiltinIgnoreTagsEnabled: utils.ConvertBoolToPointer(false),
		CustomIgnoreTags: []*wiz.CICDPolicyCustomIgnoreTagCreateInput{
			{
				Key:   "eb9b5425-1635-4cf6-a7b1-44f015795efc",
				Value: "cdebef02-fc13-472e-a4cc-2fe4d355c924",
				RuleIDs: []string{
					"f53784f1-a676-489b-aae6-6672e7005a5f",
					"16eae9f8-b2b7-4cfe-9bff-b828f65d459a",
				},
				IgnoreAllRules: utils.ConvertBoolToPointer(false),
			},
		},
		SecurityFrameworks: []string{
			"5add2652-f417-4050-85de-c1c00c4a6a3c",
			"57fb812b-1220-41c8-b71b-200abbf32c98",
		},
	}

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "5fdb33cc-5b36-46ee-9d71-b7282d06271a",
			"iac_params": []interface{}{
				map[string]interface{}{
					"severity_threshold": "5f45a8d4-24b2-463d-b604-ca532e4ec4d3",
					"count_threshold":    3,
					"ignored_rules": []interface{}{
						"1c1e4a07-8062-4c40-849f-b41417887768",
						"3f25530e-3295-462e-a300-4ef456291263",
					},
					"builtin_ignore_tags_enabled": false,
					"custom_ignore_tags": []interface{}{
						map[string]interface{}{
							"key":   "eb9b5425-1635-4cf6-a7b1-44f015795efc",
							"value": "cdebef02-fc13-472e-a4cc-2fe4d355c924",
							"rule_ids": []interface{}{
								"f53784f1-a676-489b-aae6-6672e7005a5f",
								"16eae9f8-b2b7-4cfe-9bff-b828f65d459a",
							},
							"ignore_all_rules": false,
						},
					},
					"security_frameworks": []interface{}{
						"5add2652-f417-4050-85de-c1c00c4a6a3c",
						"57fb812b-1220-41c8-b71b-200abbf32c98",
					},
				},
			},
		},
	)

	cicdParams := getIACParamsForCreate(ctx, d)

	if !reflect.DeepEqual(expected, cicdParams) {
		t.Fatalf(
			expectedTestError,
			cicdParams,
			expected,
		)
	}
}

func TestGetPolicyLifecycleEnforcementsForCreate(t *testing.T) {
	ctx := context.Background()

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "test-policy",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "BLOCK",
				},
				map[string]interface{}{
					"deployment_lifecycle": "CODE",
					"enforcement_method":   "BLOCK",
				},
			},
			"iac_params": []interface{}{
				map[string]interface{}{
					"severity_threshold": "CRITICAL",
					"count_threshold":    3,
				},
			},
		},
	)

	result := getPolicyLifecycleEnforcementsForCreate(ctx, d)

	// Check that we have exactly 2 items
	if len(result) != 2 {
		t.Fatalf("Expected 2 policy lifecycle enforcements, got %d", len(result))
	}

	// Check that both CLI and CODE enforcements exist with BLOCK method
	foundCLI := false
	foundCODE := false
	for _, enforcement := range result {
		if enforcement.DeploymentLifecycle == "CLI" && enforcement.EnforcementMethod == "BLOCK" {
			foundCLI = true
		}
		if enforcement.DeploymentLifecycle == "CODE" && enforcement.EnforcementMethod == "BLOCK" {
			foundCODE = true
		}
	}

	if !foundCLI {
		t.Fatal("Expected CLI enforcement with BLOCK method not found")
	}
	if !foundCODE {
		t.Fatal("Expected CODE enforcement with BLOCK method not found")
	}
}

func TestGetPolicyLifecycleEnforcementsForCreateSingle(t *testing.T) {
	ctx := context.Background()

	expected := []wiz.PolicyLifecycleEnforcementInput{
		{
			DeploymentLifecycle: "CLI",
			EnforcementMethod:   "AUDIT",
		},
	}

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "test-policy-single",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "AUDIT",
				},
			},
			"disk_secrets_params": []interface{}{
				map[string]interface{}{
					"count_threshold": 3,
				},
			},
		},
	)

	result := getPolicyLifecycleEnforcementsForCreate(ctx, d)

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf(
			expectedTestError,
			result,
			expected,
		)
	}
}

func TestFlattenPolicyLifecycleEnforcements(t *testing.T) {
	ctx := context.Background()

	input := []wiz.PolicyLifecycleEnforcementOutput{
		{
			DeploymentLifecycle: "CLI",
			EnforcementMethod:   "BLOCK",
		},
		{
			DeploymentLifecycle: "CODE",
			EnforcementMethod:   "AUDIT",
		},
	}

	expected := []interface{}{
		map[string]interface{}{
			"deployment_lifecycle": "CLI",
			"enforcement_method":   "BLOCK",
			"enforcement_config":   []interface{}{},
		},
		map[string]interface{}{
			"deployment_lifecycle": "CODE",
			"enforcement_method":   "AUDIT",
			"enforcement_config":   []interface{}{},
		},
	}

	result := flattenPolicyLifecycleEnforcements(ctx, input)

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf(
			expectedTestError,
			result,
			expected,
		)
	}
}

func TestFlattenPolicyLifecycleEnforcementsEmpty(t *testing.T) {
	ctx := context.Background()

	input := []wiz.PolicyLifecycleEnforcementOutput{}

	result := flattenPolicyLifecycleEnforcements(ctx, input)

	// For empty input, result should be an empty slice (length 0)
	if len(result) != 0 {
		t.Fatalf("Expected empty slice, got %d items: %v", len(result), result)
	}
}

func TestFlattenPolicyLifecycleEnforcementsWithAdmissionController(t *testing.T) {
	ctx := context.Background()

	enforceOnScope := true
	input := []wiz.PolicyLifecycleEnforcementOutput{
		{
			DeploymentLifecycle: "ADMISSION_CONTROLLER",
			EnforcementMethod:   "BLOCK",
			EnforcementConfig: &wiz.PolicyLifecycleEnforcementConfigOutput{
				EnforceOnScope: &enforceOnScope,
			},
		},
	}

	expected := []interface{}{
		map[string]interface{}{
			"deployment_lifecycle": "ADMISSION_CONTROLLER",
			"enforcement_method":   "BLOCK",
			"enforcement_config": []interface{}{
				map[string]interface{}{
					"admission_controller_config": []interface{}{
						map[string]interface{}{
							"enforce_on_scope": true,
						},
					},
				},
			},
		},
	}

	result := flattenPolicyLifecycleEnforcements(ctx, input)

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf(
			expectedTestError,
			result,
			expected,
		)
	}
}

func TestHandlePolicyLifecycleEnforcementsUpdate(t *testing.T) {
	ctx := context.Background()

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "test-update-policy",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "BLOCK",
				},
				map[string]interface{}{
					"deployment_lifecycle": "CODE",
					"enforcement_method":   "AUDIT",
				},
			},
			"disk_vulnerabilities_params": []interface{}{
				map[string]interface{}{
					"severity":                "HIGH",
					"package_count_threshold": 5,
					"ignore_unfixed":          true,
					"package_allow_list":      []interface{}{},
				},
			},
		},
	)

	result := handlePolicyLifecycleEnforcementsUpdate(ctx, d)

	// Check that we have exactly 2 items
	if len(result) != 2 {
		t.Fatalf("Expected 2 policy lifecycle enforcements, got %d", len(result))
	}

	// Check that both CLI and CODE enforcements exist with correct methods
	foundCLI := false
	foundCODE := false
	for _, enforcement := range result {
		if enforcement.DeploymentLifecycle == "CLI" && enforcement.EnforcementMethod == "BLOCK" {
			foundCLI = true
		}
		if enforcement.DeploymentLifecycle == "CODE" && enforcement.EnforcementMethod == "AUDIT" {
			foundCODE = true
		}
	}

	if !foundCLI {
		t.Fatal("Expected CLI enforcement with BLOCK method not found")
	}
	if !foundCODE {
		t.Fatal("Expected CODE enforcement with AUDIT method not found")
	}
}

func TestGetPolicyLifecycleEnforcementsForCreateWithAdmissionController(t *testing.T) {
	ctx := context.Background()

	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name": "test-admission-controller-policy",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "ADMISSION_CONTROLLER",
					"enforcement_method":   "BLOCK",
					"enforcement_config": []interface{}{
						map[string]interface{}{
							"admission_controller_config": []interface{}{
								map[string]interface{}{
									"enforce_on_scope": true,
								},
							},
						},
					},
				},
			},
			"iac_params": []interface{}{
				map[string]interface{}{
					"severity_threshold": "CRITICAL",
					"count_threshold":    3,
				},
			},
		},
	)

	result := getPolicyLifecycleEnforcementsForCreate(ctx, d)

	// Check that we have exactly 1 item
	if len(result) != 1 {
		t.Fatalf("Expected 1 policy lifecycle enforcement, got %d", len(result))
	}

	enforcement := result[0]

	// Check basic fields
	if enforcement.DeploymentLifecycle != "ADMISSION_CONTROLLER" {
		t.Fatalf("Expected deployment lifecycle ADMISSION_CONTROLLER, got %s", enforcement.DeploymentLifecycle)
	}
	if enforcement.EnforcementMethod != "BLOCK" {
		t.Fatalf("Expected enforcement method BLOCK, got %s", enforcement.EnforcementMethod)
	}

	// Check enforcement config
	if enforcement.EnforcementConfig == nil {
		t.Fatal("Expected enforcement config to be set")
	}
	if enforcement.EnforcementConfig.AdmissionControllerConfig == nil {
		t.Fatal("Expected admission controller config to be set")
	}
	if !enforcement.EnforcementConfig.AdmissionControllerConfig.EnforceOnScope {
		t.Fatal("Expected enforce on scope to be true")
	}
}

// Integration tests based on real-world examples
func TestCICDScanPolicyIntegrationIAC(t *testing.T) {
	ctx := context.Background()

	// Test IAC scan policy similar to the terraform-test-iac example
	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name":        "terraform-test-iac",
			"description": "terraform-test-iac description",
			"project_ids": []interface{}{},
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "BLOCK",
				},
				map[string]interface{}{
					"deployment_lifecycle": "CODE",
					"enforcement_method":   "BLOCK",
				},
			},
			"iac_params": []interface{}{
				map[string]interface{}{
					"count_threshold":     3,
					"severity_threshold":  "CRITICAL",
					"ignored_rules":       []interface{}{},
					"security_frameworks": []interface{}{},
				},
			},
		},
	)

	// Test the create functions work together
	enforcements := getPolicyLifecycleEnforcementsForCreate(ctx, d)
	iacParams := getIACParamsForCreate(ctx, d)

	// Verify enforcements
	if len(enforcements) != 2 {
		t.Fatalf("Expected 2 policy lifecycle enforcements, got %d", len(enforcements))
	}

	// Verify IAC params
	if iacParams.CountThreshold != 3 {
		t.Fatalf("Expected count threshold 3, got %d", iacParams.CountThreshold)
	}
	if iacParams.SeverityThreshold != "CRITICAL" {
		t.Fatalf("Expected severity threshold CRITICAL, got %s", iacParams.SeverityThreshold)
	}
}

func TestCICDScanPolicyIntegrationSecrets(t *testing.T) {
	ctx := context.Background()

	// Test Secrets scan policy similar to the terraform-test-secrets example
	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name":        "terraform-test-secrets",
			"description": "terraform-test-secrets description",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "BLOCK",
				},
			},
			"disk_secrets_params": []interface{}{
				map[string]interface{}{
					"count_threshold": 3,
					"path_allow_list": []interface{}{},
				},
			},
		},
	)

	// Test the create functions work together
	enforcements := getPolicyLifecycleEnforcementsForCreate(ctx, d)
	secretsParams := getDiskSecretsParams(ctx, d)

	// Verify enforcements - only CLI should be present
	if len(enforcements) != 1 {
		t.Fatalf("Expected 1 policy lifecycle enforcement, got %d", len(enforcements))
	}
	if enforcements[0].DeploymentLifecycle != "CLI" || enforcements[0].EnforcementMethod != "BLOCK" {
		t.Fatalf("Expected CLI/BLOCK enforcement, got %s/%s", enforcements[0].DeploymentLifecycle, enforcements[0].EnforcementMethod)
	}

	// Verify secrets params
	if secretsParams.CountThreshold != 3 {
		t.Fatalf("Expected count threshold 3, got %d", secretsParams.CountThreshold)
	}
}

func TestCICDScanPolicyIntegrationVulnerabilities(t *testing.T) {
	ctx := context.Background()

	// Test Vulnerabilities scan policy similar to the terraform-test-vulnerabilities example
	d := schema.TestResourceDataRaw(
		t,
		resourceWizCICDScanPolicy().Schema,
		map[string]interface{}{
			"name":        "terraform-test-vulnerabilities",
			"description": "terraform-test-vulnerabilities description",
			"policy_lifecycle_enforcements": []interface{}{
				map[string]interface{}{
					"deployment_lifecycle": "CLI",
					"enforcement_method":   "BLOCK",
				},
			},
			"disk_vulnerabilities_params": []interface{}{
				map[string]interface{}{
					"package_allow_list":      []interface{}{},
					"package_count_threshold": 3,
					"severity":                "HIGH",
					"ignore_unfixed":          false,
				},
			},
		},
	)

	// Test the create functions work together
	enforcements := getPolicyLifecycleEnforcementsForCreate(ctx, d)
	vulnParams := getDiskVulnerabilitiesParams(ctx, d)

	// Verify enforcements - only CLI should be present
	if len(enforcements) != 1 {
		t.Fatalf("Expected 1 policy lifecycle enforcement, got %d", len(enforcements))
	}
	if enforcements[0].DeploymentLifecycle != "CLI" || enforcements[0].EnforcementMethod != "BLOCK" {
		t.Fatalf("Expected CLI/BLOCK enforcement, got %s/%s", enforcements[0].DeploymentLifecycle, enforcements[0].EnforcementMethod)
	}

	// Verify vulnerability params
	if vulnParams.PackageCountThreshold != 3 {
		t.Fatalf("Expected package count threshold 3, got %d", vulnParams.PackageCountThreshold)
	}
	if vulnParams.Severity != "HIGH" {
		t.Fatalf("Expected severity HIGH, got %s", vulnParams.Severity)
	}
	if vulnParams.IgnoreUnfixed != false {
		t.Fatalf("Expected ignore_unfixed false, got %t", vulnParams.IgnoreUnfixed)
	}
}
