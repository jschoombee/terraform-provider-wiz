package acceptance

import (
	"fmt"
	"os"
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

func testResourceWizCICDScanPolicyBasic(rName string, description string, projectID string) string {
	return fmt.Sprintf(`
resource "wiz_cicd_scan_policy" "foo" {
  name        = "%s"
  description = "%s"
  project_ids = [ "%s" ]
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
