package acceptance

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const resourceWizCICDScanPolicy = "wiz_cicd_scan_policy.foo"

func TestAccResourceWizCICDScanPolicyBasic(t *testing.T) {
	rName := acctest.RandomWithPrefix(ResourcePrefix)
	updateThreshold := 3
	description := "terraform-test description"
	projectID := os.Getenv("WIZ_PROJECT_ID")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t, TestCase(TcCICDScanPolicy)) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceWizCICDScanPolicyBasic(rName, description, projectID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						description,
					),
					resource.TestCheckTypeSetElemAttr(
						resourceWizCICDScanPolicy,
						"project_ids.*",
						projectID,
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.count_threshold",
						"3",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.severity_threshold",
						"CRITICAL",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.builtin_ignore_tags_enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.ignored_rules.0",
						"fd7dd0c6-4953-4b36-bc39-004ec3d870db",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.ignored_rules.1",
						"063fb380-9eda-4c08-a31b-9211ee37bd42",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.custom_ignore_tags.0.key",
						"testkey1",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.custom_ignore_tags.0.value",
						"testval1",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.custom_ignore_tags.0.ignore_all_rules",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"iac_params.0.custom_ignore_tags.0.rule_ids.0",
						"063fb380-9eda-4c08-a31b-9211ee37bd42",
					),
					// Verify policy_lifecycle_enforcements are set (API defaults)
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.#",
						"3",
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CLI",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CODE",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "ADMISSION_CONTROLLER",
							"enforcement_method":   "AUDIT",
						},
					),
				),
			},
			{
				// simple check that description updates
				Config: testResourceWizCICDScanPolicyUpdate(rName, "new-description", updateThreshold),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						"new-description",
					),
					resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(
							resourceWizCICDScanPolicy,
							"iac_params.0.count_threshold",
							fmt.Sprintf("%d", updateThreshold),
						),
					),
				),
			},
		},
	})
}

func TestAccResourceWizCICDScanPolicyWithPolicyLifecycleEnforcements(t *testing.T) {
	rName := acctest.RandomWithPrefix(ResourcePrefix)
	description := "terraform-test with policy lifecycle enforcements"
	projectID := os.Getenv("WIZ_PROJECT_ID")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t, TestCase(TcCICDScanPolicy)) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceWizCICDScanPolicyWithPolicyLifecycle(rName, description, projectID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						description,
					),
					// Verify policy_lifecycle_enforcements are correctly set
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.#",
						"3",
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CLI",
							"enforcement_method":   "BLOCK",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CODE",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "ADMISSION_CONTROLLER",
							"enforcement_method":   "AUDIT",
						},
					),
				),
			},
			{
				// Update to change enforcement methods
				Config: testResourceWizCICDScanPolicyWithPolicyLifecycleUpdate(rName, "updated-description"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						"updated-description",
					),
					// Verify updated policy_lifecycle_enforcements
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.#",
						"3",
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CLI",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CODE",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "ADMISSION_CONTROLLER",
							"enforcement_method":   "AUDIT",
						},
					),
				),
			},
		},
	})
}

func TestAccResourceWizCICDScanPolicyValidation(t *testing.T) {
	rName := acctest.RandomWithPrefix(ResourcePrefix)
	projectID := os.Getenv("WIZ_PROJECT_ID")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t, TestCase(TcCICDScanPolicy)) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      testResourceWizCICDScanPolicyInvalidDeploymentLifecycle(rName, projectID),
				ExpectError: regexp.MustCompile("expected deployment_lifecycle to be one of"),
			},
			{
				Config:      testResourceWizCICDScanPolicyInvalidEnforcementMethod(rName, projectID),
				ExpectError: regexp.MustCompile("expected enforcement_method to be one of"),
			},
		},
	})
}

func TestAccResourceWizCICDScanPolicyWithAdmissionController(t *testing.T) {
	rName := acctest.RandomWithPrefix(ResourcePrefix)
	description := "terraform-test with admission controller config"
	projectID := os.Getenv("WIZ_PROJECT_ID")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t, TestCase(TcCICDScanPolicy)) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceWizCICDScanPolicyWithAdmissionController(rName, description, projectID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						description,
					),
					// Verify policy_lifecycle_enforcements are correctly set
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.#",
						"3",
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CLI",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CODE",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "ADMISSION_CONTROLLER",
							"enforcement_method":   "BLOCK",
						},
					),
					// Verify admission controller config
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*.enforcement_config.*.admission_controller_config.*",
						map[string]string{
							"enforce_on_scope": "true",
						},
					),
				),
			},
		},
	})
}

func TestAccResourceWizCICDScanPolicyBackwardCompatibility(t *testing.T) {
	rName := acctest.RandomWithPrefix(ResourcePrefix)
	description := "terraform-test backward compatibility - no policy lifecycle enforcements"
	projectID := os.Getenv("WIZ_PROJECT_ID")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t, TestCase(TcCICDScanPolicy)) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceWizCICDScanPolicyBackwardCompatibility(rName, description, projectID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"description",
						description,
					),
					resource.TestCheckTypeSetElemAttr(
						resourceWizCICDScanPolicy,
						"project_ids.*",
						projectID,
					),
					// Verify that API defaults are applied when no policy_lifecycle_enforcements specified
					resource.TestCheckResourceAttr(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.#",
						"3",
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CLI",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "CODE",
							"enforcement_method":   "AUDIT",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(
						resourceWizCICDScanPolicy,
						"policy_lifecycle_enforcements.*",
						map[string]string{
							"deployment_lifecycle": "ADMISSION_CONTROLLER",
							"enforcement_method":   "AUDIT",
						},
					),
				),
			},
		},
	})
}

func testResourceWizCICDScanPolicyBasic(rName string, description string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"
  project_ids = [ "%s" ]

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CODE"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "ADMISSION_CONTROLLER"
    enforcement_method   = "AUDIT"
  }

  iac_params {
    count_threshold             = 3
    severity_threshold          = "CRITICAL"
    builtin_ignore_tags_enabled = false
    ignored_rules = [
      "fd7dd0c6-4953-4b36-bc39-004ec3d870db",
      "063fb380-9eda-4c08-a31b-9211ee37bd42",
    ]
    custom_ignore_tags {
      key              = "testkey1"
      value            = "testval1"
      ignore_all_rules = false
      rule_ids = [
        "063fb380-9eda-4c08-a31b-9211ee37bd42",
      ]
    }
    custom_ignore_tags {
      key              = "testkey2"
      value            = "testval2"
      ignore_all_rules = false
      rule_ids = [
        "1f0ee3b5-5404-4b40-bbc8-33a990330ac3",
        "a1958aa1-b810-4df6-bd82-487cb37c6039",
      ]
    }
  }
}
`, rName, description, projectID)
}

func testResourceWizCICDScanPolicyUpdate(rName string, description string, countThreshold int) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CODE"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "ADMISSION_CONTROLLER"
    enforcement_method   = "AUDIT"
  }

  iac_params {
    count_threshold             = %d
    severity_threshold          = "CRITICAL"
    builtin_ignore_tags_enabled = false
    ignored_rules = [
      "fd7dd0c6-4953-4b36-bc39-004ec3d870db",
      "063fb380-9eda-4c08-a31b-9211ee37bd42",
    ]
    custom_ignore_tags {
      key              = "testkey1"
      value            = "testval1"
      ignore_all_rules = false
      rule_ids = [
        "063fb380-9eda-4c08-a31b-9211ee37bd42",
      ]
    }
    custom_ignore_tags {
      key              = "testkey2"
      value            = "testval2"
      ignore_all_rules = false
      rule_ids = [
        "1f0ee3b5-5404-4b40-bbc8-33a990330ac3",
        "a1958aa1-b810-4df6-bd82-487cb37c6039",
      ]
    }
  }
}
`, rName, description, countThreshold)
}

func testResourceWizCICDScanPolicyWithPolicyLifecycle(rName string, description string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"
  project_ids = [ "%s" ]

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "BLOCK"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CODE"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "ADMISSION_CONTROLLER"
    enforcement_method   = "AUDIT"
  }

  iac_params {
    count_threshold             = 3
    severity_threshold          = "CRITICAL"
    builtin_ignore_tags_enabled = false
    ignored_rules = [
      "fd7dd0c6-4953-4b36-bc39-004ec3d870db",
    ]
  }
}
`, rName, description, projectID)
}

func testResourceWizCICDScanPolicyWithPolicyLifecycleUpdate(rName string, description string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CODE"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "ADMISSION_CONTROLLER"
    enforcement_method   = "AUDIT"
  }

  iac_params {
    count_threshold             = 5
    severity_threshold          = "HIGH"
    builtin_ignore_tags_enabled = true
  }
}
`, rName, description)
}

func testResourceWizCICDScanPolicyInvalidDeploymentLifecycle(rName string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "test invalid deployment lifecycle"
  project_ids = [ "%s" ]

  policy_lifecycle_enforcements {
    deployment_lifecycle = "INVALID_LIFECYCLE"
    enforcement_method   = "BLOCK"
  }

  iac_params {
    count_threshold    = 3
    severity_threshold = "CRITICAL"
  }
}
`, rName, projectID)
}

func testResourceWizCICDScanPolicyInvalidEnforcementMethod(rName string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "test invalid enforcement method"
  project_ids = [ "%s" ]

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "INVALID_METHOD"
  }

  iac_params {
    count_threshold    = 3
    severity_threshold = "CRITICAL"
  }
}
`, rName, projectID)
}

func testResourceWizCICDScanPolicyWithAdmissionController(rName string, description string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"
  project_ids = [ "%s" ]

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CLI"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "CODE"
    enforcement_method   = "AUDIT"
  }

  policy_lifecycle_enforcements {
    deployment_lifecycle = "ADMISSION_CONTROLLER"
    enforcement_method   = "BLOCK"
    enforcement_config {
      admission_controller_config {
        enforce_on_scope = true
      }
    }
  }

  iac_params {
    count_threshold             = 3
    severity_threshold          = "CRITICAL"
    builtin_ignore_tags_enabled = false
  }
}
`, rName, description, projectID)
}

func testResourceWizCICDScanPolicyBackwardCompatibility(rName string, description string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"
  project_ids = [ "%s" ]

  iac_params {
    count_threshold             = 5
    severity_threshold          = "HIGH"
    builtin_ignore_tags_enabled = true
    ignored_rules = [
      "fd7dd0c6-4953-4b36-bc39-004ec3d870db",
    ]
  }
}
`, rName, description, projectID)
}
