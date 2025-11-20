package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"wiz.io/hashicorp/terraform-provider-wiz/internal"
	"wiz.io/hashicorp/terraform-provider-wiz/internal/client"
	"wiz.io/hashicorp/terraform-provider-wiz/internal/utils"
	"wiz.io/hashicorp/terraform-provider-wiz/internal/wiz"
)

type CICDPolicyCustomIgnoreTag interface {
	SetKey(key string)
	SetValue(value string)
	SetIgnoreAllRules(ignoreAllRules *bool)
	SetRuleIDs(ruleIDs []string)
}

type CICDPolicyCustomIgnoreTagCreateWrapper struct {
	*wiz.CICDPolicyCustomIgnoreTagCreateInput
}

func (tag *CICDPolicyCustomIgnoreTagCreateWrapper) SetKey(key string) {
	tag.Key = key
}

func (tag *CICDPolicyCustomIgnoreTagCreateWrapper) SetValue(value string) {
	tag.Value = value
}

func (tag *CICDPolicyCustomIgnoreTagCreateWrapper) SetIgnoreAllRules(ignoreAllRules *bool) {
	tag.IgnoreAllRules = ignoreAllRules
}

func (tag *CICDPolicyCustomIgnoreTagCreateWrapper) SetRuleIDs(ruleIDs []string) {
	tag.RuleIDs = ruleIDs
}

type CICDPolicyCustomIgnoreTagUpdateWrapper struct {
	*wiz.CICDPolicyCustomIgnoreTagUpdateInput
}

func (tag *CICDPolicyCustomIgnoreTagUpdateWrapper) SetKey(key string) {
	tag.Key = key
}

func (tag *CICDPolicyCustomIgnoreTagUpdateWrapper) SetValue(value string) {
	tag.Value = value
}

func (tag *CICDPolicyCustomIgnoreTagUpdateWrapper) SetIgnoreAllRules(ignoreAllRules *bool) {
	tag.IgnoreAllRules = ignoreAllRules
}

func (tag *CICDPolicyCustomIgnoreTagUpdateWrapper) SetRuleIDs(ruleIDs []string) {
	tag.RuleIDs = ruleIDs
}

func handleCustomIgnoreTagsGeneric(ctx context.Context, c interface{}, tagType string) []CICDPolicyCustomIgnoreTag {
	var customTags []CICDPolicyCustomIgnoreTag

	for _, f := range c.(*schema.Set).List() {
		tflog.Trace(ctx, fmt.Sprintf("f: %T %s", f, f))
		var customTag CICDPolicyCustomIgnoreTag
		switch tagType {
		case "create":
			customTag = &CICDPolicyCustomIgnoreTagCreateWrapper{
				CICDPolicyCustomIgnoreTagCreateInput: &wiz.CICDPolicyCustomIgnoreTagCreateInput{},
			}
		case "update":
			customTag = &CICDPolicyCustomIgnoreTagUpdateWrapper{
				CICDPolicyCustomIgnoreTagUpdateInput: &wiz.CICDPolicyCustomIgnoreTagUpdateInput{},
			}
		default:
			tflog.Warn(ctx, fmt.Sprintf("Unknown tag type: %s", tagType))
			continue
		}

		for g, h := range f.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf("g: %T %s", g, g))
			tflog.Trace(ctx, fmt.Sprintf("h: %T %s", h, h))
			switch g {
			case "key":
				customTag.SetKey(h.(string))
			case "value":
				customTag.SetValue(h.(string))
			case "ignore_all_rules":
				customTag.SetIgnoreAllRules(utils.ConvertBoolToPointer(h.(bool)))
			case "rule_ids":
				customTag.SetRuleIDs(utils.ConvertListToString(h.([]interface{})))
			default:
				tflog.Warn(ctx, fmt.Sprintf("unknown custom_ignore_tags param: %s", g))
			}
		}
		tflog.Debug(ctx, fmt.Sprintf("customTag: %s", utils.PrettyPrint(customTag)))
		customTags = append(customTags, customTag)
	}

	return customTags
}

const paramsFormat = "params %T %s"
const paramsFormatDebug = "a: %T %d"

func resourceWizCICDScanPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Configure CI/CD Scan Policies.",
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "Internal identifier",
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the Scan Policy.",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the Scan Policy.",
				Optional:    true,
			},
			"builtin": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"project_ids": {
				Description: "The project IDs that the scan policy applies to.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew: true, // connect reassign project scoping
			},
			"type": {
				Type:        schema.TypeString,
				Description: "The scan policy type",
				Computed:    true,
			},
			"disk_vulnerabilities_params": {
				Type:        schema.TypeSet,
				Description: "Vulnerability scan parameters.",
				Optional:    true,
				MaxItems:    1,
				ExactlyOneOf: []string{
					"disk_vulnerabilities_params",
					"disk_secrets_params",
					"iac_params",
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"severity": {
							Type:     schema.TypeString,
							Required: true,
							Description: fmt.Sprintf(
								"Severity.\n    - Allowed values: %s",
								utils.SliceOfStringToMDUList(
									wiz.DiskScanVulnerabilitySeverity,
								),
							),
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice(
									wiz.DiskScanVulnerabilitySeverity,
									false,
								),
							),
						},
						"package_count_threshold": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"ignore_unfixed": {
							Type:     schema.TypeBool,
							Required: true,
						},
						"package_allow_list": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"disk_secrets_params": {
				Type:        schema.TypeSet,
				Description: "Secret scan parameters.",
				Optional:    true,
				MaxItems:    1,
				ExactlyOneOf: []string{
					"disk_vulnerabilities_params",
					"disk_secrets_params",
					"iac_params",
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"count_threshold": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"path_allow_list": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"iac_params": {
				Type:        schema.TypeSet,
				Description: "IaC scan parameters.",
				Optional:    true,
				MaxItems:    1,
				ExactlyOneOf: []string{
					"disk_vulnerabilities_params",
					"disk_secrets_params",
					"iac_params",
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"severity_threshold": {
							Type:     schema.TypeString,
							Required: true,
							Description: fmt.Sprintf(
								"Severity threshold.\n    - Allowed values: %s",
								utils.SliceOfStringToMDUList(
									wiz.IACScanSeverity,
								),
							),
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice(
									wiz.IACScanSeverity,
									false,
								),
							),
						},
						"count_threshold": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"ignored_rules": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"builtin_ignore_tags_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"custom_ignore_tags": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
									"rule_ids": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"ignore_all_rules": {
										Type:     schema.TypeBool,
										Optional: true,
									},
								},
							},
						},
						"security_frameworks": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"policy_lifecycle_enforcements": {
				Type:        schema.TypeSet,
				Description: "Policy enforcement method by deployment lifecycle.\n\nYou must create exactly one separate block for each deployment lifecycle type you wish to configure. For example, establish one block for the CLI deployment lifecycle and/or one for the ADMISSION_CONTROLLER deployment lifecycle.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"deployment_lifecycle": {
							Type: schema.TypeString,
							Description: fmt.Sprintf(
								"Policy deployment lifecycle.\n    - Allowed values: %s",
								utils.SliceOfStringToMDUList(
									wiz.PolicyEnforcementLifecycle,
								),
							),
							Required: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice(
									wiz.PolicyEnforcementLifecycle,
									false,
								),
							),
						},
						"enforcement_method": {
							Type: schema.TypeString,
							Description: fmt.Sprintf(
								"Policy enforcement method.\n    - Allowed values: %s",
								utils.SliceOfStringToMDUList(
									wiz.PolicyEnforcementMethod,
								),
							),
							Required: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice(
									wiz.PolicyEnforcementMethod,
									false,
								),
							),
						},
						"enforcement_config": {
							Type:        schema.TypeSet,
							Description: "Policy enforcement configuration for specific deployment lifecycle types.",
							Optional:    true,
							MaxItems:    1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"admission_controller_config": {
										Type:        schema.TypeSet,
										Description: "Admission controller specific enforcement configuration. Only applicable when deployment_lifecycle is ADMISSION_CONTROLLER.",
										Optional:    true,
										MaxItems:    1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"enforce_on_scope": {
													Type:        schema.TypeBool,
													Description: "Enforce policy on all resources in the scope.",
													Required:    true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		CreateContext: resourceWizCICDScanPolicyCreate,
		ReadContext:   resourceWizCICDScanPolicyRead,
		UpdateContext: resourceWizCICDScanPolicyUpdate,
		DeleteContext: resourceWizCICDScanPolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

// CreateCICDScanPolicy struct
type CreateCICDScanPolicy struct {
	CreateCICDScanPolicy wiz.CreateCICDScanPolicyPayload `json:"createCICDScanPolicy"`
}

func getDiskVulnerabilitiesParams(ctx context.Context, d *schema.ResourceData) *wiz.CreateCICDScanPolicyDiskVulnerabilitiesInput {
	tflog.Info(ctx, "getDiskVulnerabilitiesParams called...")

	// return var
	var output wiz.CreateCICDScanPolicyDiskVulnerabilitiesInput

	// fetch and walk the structure
	params := d.Get("disk_vulnerabilities_params").(*schema.Set).List()
	for _, a := range params {
		tflog.Trace(ctx, fmt.Sprintf("disk_vulnerabilities_params param: %T %s", a, utils.PrettyPrint(a)))
		for b, c := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf(logInterfaceType, b, b))
			tflog.Trace(ctx, fmt.Sprintf("disk_vulnerabilities_params c: %T %s", c, c))
			switch b {
			case "severity":
				output.Severity = c.(string)
			case "package_count_threshold":
				output.PackageCountThreshold = c.(int)
			case "ignore_unfixed":
				output.IgnoreUnfixed = c.(bool)
			case "package_allow_list":
				output.PackageAllowList = utils.ConvertListToString(c.([]interface{}))
			default:
				tflog.Warn(ctx, fmt.Sprintf("unknown parameter: %s", b))
			}

		}
	}

	return &output
}

func getDiskSecretsParams(ctx context.Context, d *schema.ResourceData) *wiz.CreateCICDScanPolicyDiskSecretsInput {
	tflog.Info(ctx, "getDiskSecretsParams called...")

	// return var
	var output wiz.CreateCICDScanPolicyDiskSecretsInput

	// fetch and walk the structure
	params := d.Get("disk_secrets_params").(*schema.Set).List()
	for _, a := range params {
		tflog.Trace(ctx, fmt.Sprintf("param: %T %s", a, utils.PrettyPrint(a)))
		for b, c := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf(logInterfaceType, b, b))
			tflog.Trace(ctx, fmt.Sprintf("c: %T %s", c, c))
			switch b {
			case "count_threshold":
				output.CountThreshold = c.(int)
			case "path_allow_list":
				output.PathAllowList = utils.ConvertListToString(c.([]interface{}))
			default:
				tflog.Warn(ctx, fmt.Sprintf("unknown disk_secrets_params param: %s", b))
			}
		}
	}

	return &output
}

func handleEnforcementConfig(ctx context.Context, configSet *schema.Set) *wiz.PolicyLifecycleEnforcementConfigInput {
	if configSet.Len() == 0 {
		return nil
	}

	configList := configSet.List()
	if len(configList) == 0 {
		return nil
	}

	configItem := configList[0].(map[string]interface{})
	config := &wiz.PolicyLifecycleEnforcementConfigInput{}

	for key, value := range configItem {
		switch key {
		case "admission_controller_config":
			if admissionSet, ok := value.(*schema.Set); ok && admissionSet.Len() > 0 {
				admissionList := admissionSet.List()
				if len(admissionList) > 0 {
					admissionConfig := admissionList[0].(map[string]interface{})
					config.AdmissionControllerConfig = &wiz.PolicyLifecycleEnforcementConfigAdmissionControllerInput{
						EnforceOnScope: admissionConfig["enforce_on_scope"].(bool),
					}
				}
			}
		default:
			tflog.Warn(ctx, fmt.Sprintf("unknown enforcement_config param: %s", key))
		}
	}

	return config
}

func getPolicyLifecycleEnforcementsForCreate(ctx context.Context, d *schema.ResourceData) []wiz.PolicyLifecycleEnforcementInput {
	tflog.Info(ctx, "getPolicyLifecycleEnforcementsForCreate called...")

	var enforcements []wiz.PolicyLifecycleEnforcementInput

	// fetch and walk the structure
	params := d.Get("policy_lifecycle_enforcements").(*schema.Set).List()
	for _, a := range params {
		tflog.Trace(ctx, fmt.Sprintf("policy_lifecycle_enforcements param: %T %s", a, utils.PrettyPrint(a)))

		enforcement := wiz.PolicyLifecycleEnforcementInput{}

		for b, c := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf(logInterfaceType, b, b))
			tflog.Trace(ctx, fmt.Sprintf("policy_lifecycle_enforcements c: %T %s", c, c))
			switch b {
			case "deployment_lifecycle":
				enforcement.DeploymentLifecycle = c.(string)
			case "enforcement_method":
				enforcement.EnforcementMethod = c.(string)
			case "enforcement_config":
				// Handle enforcement config if provided
				if configSet, ok := c.(*schema.Set); ok && configSet.Len() > 0 {
					enforcement.EnforcementConfig = handleEnforcementConfig(ctx, configSet)
				}
			default:
				tflog.Warn(ctx, fmt.Sprintf("unknown policy_lifecycle_enforcements param: %s", b))
			}
		}

		tflog.Debug(ctx, fmt.Sprintf("enforcement: %s", utils.PrettyPrint(enforcement)))
		enforcements = append(enforcements, enforcement)
	}

	return enforcements
}

func getIACParamsForCreate(ctx context.Context, d *schema.ResourceData) *wiz.CreateCICDScanPolicyIACInput {
	tflog.Info(ctx, "getIACParamsForCreate called...")

	// return var
	var output wiz.CreateCICDScanPolicyIACInput
	var customTags []*wiz.CICDPolicyCustomIgnoreTagCreateInput

	// fetch and walk the structure
	params := d.Get("iac_params").(*schema.Set).List()
	for _, a := range params {
		tflog.Trace(ctx, fmt.Sprintf("param: %T %s", a, utils.PrettyPrint(a)))
		for b, c := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf(logInterfaceType, b, b))
			tflog.Trace(ctx, fmt.Sprintf("c: %T %s", c, c))
			switch b {
			case "severity_threshold":
				output.SeverityThreshold = c.(string)
			case "count_threshold":
				output.CountThreshold = c.(int)
			case "ignored_rules":
				output.IgnoredRules = utils.ConvertListToString(c.([]interface{}))
			case "builtin_ignore_tags_enabled":
				output.BuiltinIgnoreTagsEnabled = utils.ConvertBoolToPointer(c.(bool))
			case "security_frameworks":
				output.SecurityFrameworks = utils.ConvertListToString(c.([]interface{}))
			case "custom_ignore_tags":
				customTags = handleCustomIgnoreTagsCreate(ctx, c)
			default:
				tflog.Warn(ctx, fmt.Sprintf("unknown iac_params param: %s", b))
			}
		}
	}
	tflog.Debug(ctx, fmt.Sprintf("customTags: %s", utils.PrettyPrint(customTags)))
	output.CustomIgnoreTags = customTags

	return &output
}

func resourceWizCICDScanPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diags diag.Diagnostics) {
	tflog.Info(ctx, "resourceWizCICDScanPolicyCreate called...")

	// define the graphql query
	query := `mutation CreateCICDScanPolicy(
	    $input: CreateCICDScanPolicyInput!
	) {
	    createCICDScanPolicy (
	        input: $input
	    ) {
	        scanPolicy
	        {
	            id
	            builtin
	        }
	    }
	}`

	// populate the graphql variables
	vars := &wiz.CreateCICDScanPolicyInput{}

	vars.Name = d.Get("name").(string)
	vars.Description = d.Get("description").(string)

	if v, ok := d.GetOk("project_ids"); ok {
		vars.ProjectIDs = utils.ConvertListToString(v.([]any))
	}

	// Handle policy lifecycle enforcements
	if enforcements := getPolicyLifecycleEnforcementsForCreate(ctx, d); len(enforcements) > 0 {
		vars.PolicyLifecycleEnforcements = &enforcements
	}

	policyType, diags := setPolicyType(ctx, d)
	if len(diags) > 0 {
		return diags
	}

	switch policyType {
	case "CICDScanPolicyParamsVulnerabilities":
		vars.DiskVulnerabilitiesParams = getDiskVulnerabilitiesParams(ctx, d)
	case "CICDScanPolicyParamsSecrets":
		vars.DiskSecretsParams = getDiskSecretsParams(ctx, d)
	case "CICDScanPolicyParamsIAC":
		vars.IACParams = getIACParamsForCreate(ctx, d)
	default:
		tflog.Error(ctx, fmt.Sprintf("Unknown policy type: %s", policyType))
	}

	// process the request
	data := &CreateCICDScanPolicy{}
	requestDiags := client.ProcessRequest(ctx, m, vars, data, query, "cicd_scan_policy", "create")
	diags = append(diags, requestDiags...)
	if len(diags) > 0 {
		return diags
	}

	// set the id and computed values
	d.SetId(data.CreateCICDScanPolicy.ScanPolicy.ID)
	err := d.Set("builtin", data.CreateCICDScanPolicy.ScanPolicy.Builtin)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("type", policyType)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceWizCICDScanPolicyRead(ctx, d, m)
}

func handleCustomIgnoreTagsCreate(ctx context.Context, c interface{}) []*wiz.CICDPolicyCustomIgnoreTagCreateInput {
	tags := handleCustomIgnoreTagsGeneric(ctx, c, "create")
	var customTags []*wiz.CICDPolicyCustomIgnoreTagCreateInput
	for _, tag := range tags {
		customTags = append(customTags, tag.(*CICDPolicyCustomIgnoreTagCreateWrapper).CICDPolicyCustomIgnoreTagCreateInput)
	}
	return customTags
}

func handleCustomIgnoreTagsUpdate(ctx context.Context, c interface{}) []*wiz.CICDPolicyCustomIgnoreTagUpdateInput {
	tags := handleCustomIgnoreTagsGeneric(ctx, c, "update")
	var customTags []*wiz.CICDPolicyCustomIgnoreTagUpdateInput
	for _, tag := range tags {
		customTags = append(customTags, tag.(*CICDPolicyCustomIgnoreTagUpdateWrapper).CICDPolicyCustomIgnoreTagUpdateInput)
	}
	return customTags
}

func handleSecretsParams(ctx context.Context, params interface{}) map[string]interface{} {
	// initialize the member
	var myParams = make(map[string]interface{})
	tflog.Debug(ctx, "Handling CICDScanPolicyParamsSecrets")

	// convert generic params to specific type
	tflog.Debug(ctx, fmt.Sprintf(paramsFormat, params, utils.PrettyPrint(params)))
	jsonString, _ := json.Marshal(params)
	myCICDScanPolicyParamsSecrets := &wiz.CICDScanPolicyParamsSecrets{}
	if err := json.Unmarshal(jsonString, &myCICDScanPolicyParamsSecrets); err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error unmarshalling CICDScanPolicyParamsSecrets: %s", err))
		return nil
	}

	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"myCICDScanPolicyParamsSecrets %T %s",
			myCICDScanPolicyParamsSecrets,
			utils.PrettyPrint(
				myCICDScanPolicyParamsSecrets,
			),
		),
	)

	myParams["count_threshold"] = myCICDScanPolicyParamsSecrets.CountThreshold

	var pathAllowList = make([]interface{}, 0)
	for a, b := range myCICDScanPolicyParamsSecrets.PathAllowList {
		tflog.Debug(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Debug(ctx, fmt.Sprintf(logInterfaceType, b, utils.PrettyPrint(b)))
		pathAllowList = append(pathAllowList, b)
	}
	myParams["path_allow_list"] = pathAllowList

	return myParams
}

func handleVulnerabilitiesParams(ctx context.Context, params interface{}) map[string]interface{} {
	// initialize the member
	var myParams = make(map[string]interface{})
	tflog.Debug(ctx, "Handling CICDScanPolicyParamsVulnerabilities")

	// convert generic params to specific type
	tflog.Debug(ctx, fmt.Sprintf(paramsFormat, params, utils.PrettyPrint(params)))
	jsonString, _ := json.Marshal(params)
	myCICDScanPolicyParamsVulnerabilities := &wiz.CICDScanPolicyParamsVulnerabilities{}
	if err := json.Unmarshal(jsonString, &myCICDScanPolicyParamsVulnerabilities); err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error unmarshalling CICDScanPolicyParamsVulnerabilities: %s", err))
		return nil
	}
	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"myCICDScanPolicyParamsVulnerabilities %T %s",
			myCICDScanPolicyParamsVulnerabilities,
			utils.PrettyPrint(
				myCICDScanPolicyParamsVulnerabilities,
			),
		),
	)

	myParams["ignore_unfixed"] = myCICDScanPolicyParamsVulnerabilities.IgnoreUnfixed
	myParams["package_count_threshold"] = myCICDScanPolicyParamsVulnerabilities.PackageCountThreshold
	myParams["severity"] = myCICDScanPolicyParamsVulnerabilities.Severity

	var packageAllowList = make([]interface{}, 0)
	for a, b := range myCICDScanPolicyParamsVulnerabilities.PackageAllowList {
		tflog.Debug(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Debug(ctx, fmt.Sprintf(logInterfaceType, b, utils.PrettyPrint(b)))
		packageAllowList = append(packageAllowList, b)
	}
	myParams["package_allow_list"] = packageAllowList

	return myParams
}

func handleIACParams(ctx context.Context, params interface{}) map[string]interface{} {
	// initialize the member
	var myParams = make(map[string]interface{})
	tflog.Debug(ctx, "Handling CICDScanPolicyParamsIAC")

	// convert generic params to specific type
	tflog.Debug(ctx, fmt.Sprintf(paramsFormat, params, utils.PrettyPrint(params)))
	jsonString, _ := json.Marshal(params)
	myCICDScanPolicyParamsIAC := &wiz.CICDScanPolicyParamsIAC{}

	if err := json.Unmarshal(jsonString, &myCICDScanPolicyParamsIAC); err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error unmarshalling CICDScanPolicyParamsIAC: %s", err))
		return nil
	}

	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"myCICDScanPolicyParamsIAC %T %s",
			myCICDScanPolicyParamsIAC,
			utils.PrettyPrint(
				myCICDScanPolicyParamsIAC,
			),
		),
	)

	myParams["count_threshold"] = myCICDScanPolicyParamsIAC.CountThreshold
	myParams["builtin_ignore_tags_enabled"] = myCICDScanPolicyParamsIAC.BuiltinIgnoreTagsEnabled
	myParams["severity_threshold"] = myCICDScanPolicyParamsIAC.SeverityThreshold

	var ignoredRules = make([]interface{}, 0)
	for a, b := range myCICDScanPolicyParamsIAC.IgnoredRules {
		tflog.Debug(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Debug(ctx, fmt.Sprintf(logInterfaceType, b, utils.PrettyPrint(b)))
		ignoredRules = append(ignoredRules, b.ID)
	}
	myParams["ignored_rules"] = ignoredRules

	var securityFrameWorks = make([]interface{}, 0)
	for a, b := range myCICDScanPolicyParamsIAC.SecurityFrameworks {
		tflog.Debug(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Debug(ctx, fmt.Sprintf(logInterfaceType, b, utils.PrettyPrint(b)))
		securityFrameWorks = append(securityFrameWorks, b.ID)
	}
	myParams["security_frameworks"] = securityFrameWorks

	var customIgnoreTags = make([]interface{}, 0)
	for a, b := range myCICDScanPolicyParamsIAC.CustomIgnoreTags {
		tflog.Debug(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Debug(ctx, fmt.Sprintf(logInterfaceType, b, utils.PrettyPrint(b)))
		var customIgnoreTag = make(map[string]interface{}, 0)
		customIgnoreTag["ignore_all_rules"] = b.IgnoreAllRules
		customIgnoreTag["key"] = b.Key
		customIgnoreTag["value"] = b.Value
		var rules = make([]interface{}, 0)
		for c, d := range b.Rules {
			tflog.Debug(ctx, fmt.Sprintf("c: %T %d", c, c))
			tflog.Debug(ctx, fmt.Sprintf("d: %T %s", d, utils.PrettyPrint(d)))
			rules = append(rules, d.ID)
		}
		customIgnoreTag["rule_ids"] = rules
		customIgnoreTags = append(customIgnoreTags, customIgnoreTag)
	}
	myParams["custom_ignore_tags"] = customIgnoreTags
	return myParams

}

func flattenPolicyLifecycleEnforcements(ctx context.Context, enforcements []wiz.PolicyLifecycleEnforcementOutput) []interface{} {
	tflog.Info(ctx, "flattenPolicyLifecycleEnforcements called...")

	var output []interface{}

	for _, enforcement := range enforcements {
		tflog.Trace(ctx, fmt.Sprintf("enforcement: %T %s", enforcement, utils.PrettyPrint(enforcement)))

		enforcementMap := make(map[string]interface{})
		enforcementMap["deployment_lifecycle"] = enforcement.DeploymentLifecycle
		enforcementMap["enforcement_method"] = enforcement.EnforcementMethod

		// Handle enforcement_config if present
		if enforcement.EnforcementConfig != nil {
			enforcementMap["enforcement_config"] = flattenEnforcementConfigOutput(ctx, enforcement.EnforcementConfig)
		} else {
			enforcementMap["enforcement_config"] = []interface{}{}
		}

		output = append(output, enforcementMap)
	}

	tflog.Info(ctx, fmt.Sprintf("flattenPolicyLifecycleEnforcements output: %s", utils.PrettyPrint(output)))
	return output
}

func flattenEnforcementConfig(ctx context.Context, config *wiz.PolicyLifecycleEnforcementConfigInput) []interface{} {
	if config == nil {
		return []interface{}{}
	}

	configMap := make(map[string]interface{})

	if config.AdmissionControllerConfig != nil {
		admissionConfig := []interface{}{
			map[string]interface{}{
				"enforce_on_scope": config.AdmissionControllerConfig.EnforceOnScope,
			},
		}
		configMap["admission_controller_config"] = admissionConfig
	} else {
		configMap["admission_controller_config"] = []interface{}{}
	}

	return []interface{}{configMap}
}

func flattenEnforcementConfigOutput(ctx context.Context, config *wiz.PolicyLifecycleEnforcementConfigOutput) []interface{} {
	if config == nil {
		return []interface{}{}
	}

	configMap := make(map[string]interface{})

	if config.EnforceOnScope != nil {
		admissionConfig := []interface{}{
			map[string]interface{}{
				"enforce_on_scope": *config.EnforceOnScope,
			},
		}
		configMap["admission_controller_config"] = admissionConfig
	} else {
		configMap["admission_controller_config"] = []interface{}{}
	}

	return []interface{}{configMap}
}

func flattenScanPolicyParams(ctx context.Context, paramType string, params interface{}) []interface{} {
	tflog.Info(ctx, "flattenParams called...")

	// initialize the return var
	var output = make([]interface{}, 0)

	// initialize the member
	var myParams = make(map[string]interface{})

	// log the incoming data
	tflog.Debug(ctx, fmt.Sprintf("Type %s", paramType))
	tflog.Trace(ctx, fmt.Sprintf(paramsFormat, params, utils.PrettyPrint(params)))

	// populate the structure
	switch paramType {
	case "CICDScanPolicyParamsIAC":
		myParams = handleIACParams(ctx, params)
	case "CICDScanPolicyParamsSecrets":
		myParams = handleSecretsParams(ctx, params)
	case "CICDScanPolicyParamsVulnerabilities":
		tflog.Debug(ctx, "Handling CICDScanPolicyParamsVulnerabilities")
		myParams = handleVulnerabilitiesParams(ctx, params)
	default:
		tflog.Warn(ctx, fmt.Sprintf("Unknown cicd param type: %s", paramType))
	}

	output = append(output, myParams)
	tflog.Info(ctx, fmt.Sprintf("flattenScanPolicyParams output: %s", utils.PrettyPrint(output)))
	return output
}

// ReadCICDScanPolicyPayload struct
type ReadCICDScanPolicyPayload struct {
	CICDScanPolicy wiz.CICDScanPolicy `json:"cicdScanPolicy"`
}

func resourceWizCICDScanPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diags diag.Diagnostics) {
	tflog.Info(ctx, "resourceWizCICDScanPolicyRead called...")

	// check the id
	if d.Id() == "" {
		return nil
	}

	// define the graphql query
	query := `query CICDScanPolicy  (
	    $id: ID!
	) {
	    cicdScanPolicy(
                id: $id
	    ) {
	        id
	        name
	        description
	        builtin
	        projects {
	          id
	    }
	        paramsType: params {
	            type: __typename
	        }
	        params {
	            ... on CICDScanPolicyParamsVulnerabilities {
	                severity
	                packageCountThreshold
	                ignoreUnfixed
	                packageAllowList
	            }
	            ... on CICDScanPolicyParamsSecrets {
	                countThreshold
	                pathAllowList
	            }
	            ... on CICDScanPolicyParamsIAC {
	                builtinIgnoreTagsEnabled
	                countThreshold
	                severityThreshold
	                ignoredRules {
	                    id
	                }
	                customIgnoreTags {
	                    key
	                    value
	                    ignoreAllRules
	                    rules {
	                        id
	                    }
	                }
	                securityFrameworks {
	                    id
	                }
	            }
	        }
	        policyLifecycleEnforcements {
	            enforcementMethod
	            deploymentLifecycle
	            enforcementConfig {
	                ... on PolicyLifecycleEnforcementConfigAdmissionController {
	                    enforceOnScope
	                }
	            }
	        }
	    }
	}`

	// populate the graphql variables
	vars := &internal.QueryVariables{}
	vars.ID = d.Id()

	// process the request
	// this query returns http 200 with a payload that contains errors and a null data body
	// error message: oops! an internal error has occurred. for reference purposes, this is your request id
	data := &ReadCICDScanPolicyPayload{}
	requestDiags := client.ProcessRequest(ctx, m, vars, data, query, "cicd_scan_policy", "read")
	diags = append(diags, requestDiags...)
	if len(diags) > 0 {
		tflog.Info(ctx, "Error from API call, checking if resource was deleted outside Terraform.")
		if data.CICDScanPolicy.ID == "" {
			tflog.Debug(ctx, fmt.Sprintf("Response: (%T) %s", data, utils.PrettyPrint(data)))
			tflog.Info(ctx, "Resource not found, marking as new.")
			d.SetId("")
			d.MarkNewResource()
			return nil
		}
		return diags
	}

	// set the resource parameters
	err := d.Set("name", data.CICDScanPolicy.Name)
	if err != nil {
		return append(diags, diag.FromErr(err)...)
	}
	err = d.Set("description", data.CICDScanPolicy.Description)
	if err != nil {
		return append(diags, diag.FromErr(err)...)
	}
	err = d.Set("builtin", data.CICDScanPolicy.Builtin)
	if err != nil {
		return append(diags, diag.FromErr(err)...)
	}

	projIDs := make([]string, 0)
	for _, v := range data.CICDScanPolicy.Projects {
		projIDs = append(projIDs, v.ID)
	}
	if len(projIDs) > 0 {
		err = d.Set("project_ids", projIDs)
		if err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	}

	params := flattenScanPolicyParams(ctx, data.CICDScanPolicy.ParamsType.Type, data.CICDScanPolicy.Params)
	switch data.CICDScanPolicy.ParamsType.Type {
	case "CICDScanPolicyParamsIAC":
		if err := d.Set("type", "CICDScanPolicyParamsIAC"); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
		if err := d.Set("iac_params", params); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	case "CICDScanPolicyParamsSecrets":
		if err := d.Set("type", "CICDScanPolicyParamsSecrets"); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
		if err := d.Set("disk_secrets_params", params); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	case "CICDScanPolicyParamsVulnerabilities":
		if err := d.Set("type", "CICDScanPolicyParamsVulnerabilities"); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
		if err := d.Set("disk_vulnerabilities_params", params); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	default:
		tflog.Error(ctx, fmt.Sprintf("Unknown CICDScanPolicy param type: %s", data.CICDScanPolicy.ParamsType.Type))
	}

	// Handle policy lifecycle enforcements
	if len(data.CICDScanPolicy.PolicyLifecycleEnforcements) > 0 {
		enforcements := flattenPolicyLifecycleEnforcements(ctx, data.CICDScanPolicy.PolicyLifecycleEnforcements)
		if err := d.Set("policy_lifecycle_enforcements", enforcements); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	} else {
		// Set empty array if no enforcements
		if err := d.Set("policy_lifecycle_enforcements", []interface{}{}); err != nil {
			return append(diags, diag.FromErr(err)...)
		}
	}

	return diags
}

// UpdateCICDScanPolicy struct
type UpdateCICDScanPolicy struct {
	UpdateCICDScanPolicy wiz.UpdateCICDScanPolicyPayload `json:"updateCICDScanPolicy"`
}

func handleIACParamsUpdate(ctx context.Context, d *schema.ResourceData) *wiz.UpdateCICDScanPolicyIACPatch {
	tflog.Debug(ctx, "Handling updates for CICDScanPolicyParamsIAC")
	varsType := &wiz.UpdateCICDScanPolicyIACPatch{}
	varsTypeIgnoreTags := make([]*wiz.CICDPolicyCustomIgnoreTagUpdateInput, 0)

	for _, a := range d.Get("iac_params").(*schema.Set).List() {
		tflog.Trace(ctx, fmt.Sprintf("iac_params a: (%T) %d", a, a))
		tflog.Trace(ctx, fmt.Sprintf("iac_params b: (%T) %s", a, utils.PrettyPrint(a)))
		for c, d := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf("iac_param c: (%T) %s", c, c))
			tflog.Trace(ctx, fmt.Sprintf("iac_param d: (%T) %s", d, utils.PrettyPrint(d)))
			switch c {
			case "count_threshold":
				varsType.CountThreshold = d.(int)
			case "severity_threshold":
				varsType.SeverityThreshold = d.(string)
			case "builtin_ignore_tags_enabled":
				varsType.BuiltinIgnoreTagsEnabled = utils.ConvertBoolToPointer(d.(bool))
			case "ignored_rules":
				varsType.IgnoredRules = utils.ConvertListToString(d.([]interface{}))
			case "security_frameworks":
				varsType.SecurityFrameworks = utils.ConvertListToString(d.([]interface{}))
			case "custom_ignore_tags":
				varsTypeIgnoreTags = handleCustomIgnoreTagsUpdate(ctx, d)
			default:
				tflog.Warn(ctx, fmt.Sprintf("No valid CICDScanPolicyParamsIAC case found for %s", c))
			}
		}
	}
	varsType.CustomIgnoreTags = varsTypeIgnoreTags
	return varsType
}

func handleSecretsParamsUpdate(ctx context.Context, d *schema.ResourceData) *wiz.UpdateCICDScanPolicyDiskSecretsPatch {
	tflog.Debug(ctx, "Handling updates for CICDScanPolicyParamsSecrets")
	varsType := &wiz.UpdateCICDScanPolicyDiskSecretsPatch{}

	for _, a := range d.Get("disk_secrets_params").(*schema.Set).List() {
		tflog.Trace(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Trace(ctx, fmt.Sprintf("disk_secret_params b: (%T) %s", a, utils.PrettyPrint(a)))
		for c, d := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf("CICDScanPolicyParamsSecrets c: (%T) %s", c, c))
			tflog.Trace(ctx, fmt.Sprintf("d: (%T) %s", d, utils.PrettyPrint(d)))
			switch c {
			case "count_threshold":
				varsType.CountThreshold = d.(int)
			case "path_allow_list":
				varsType.PathAllowList = utils.ConvertListToString(d.([]interface{}))
			default:
				tflog.Warn(ctx, fmt.Sprintf("No valid CICDScanPolicyParamsSecrets case found for %s", c))
			}
		}
	}

	return varsType
}

func handlePolicyLifecycleEnforcementsUpdate(ctx context.Context, d *schema.ResourceData) []wiz.PolicyLifecycleEnforcementInput {
	tflog.Debug(ctx, "Handling updates for PolicyLifecycleEnforcements")

	var enforcements []wiz.PolicyLifecycleEnforcementInput

	for _, a := range d.Get("policy_lifecycle_enforcements").(*schema.Set).List() {
		tflog.Trace(ctx, fmt.Sprintf("policy_lifecycle_enforcements a: (%T) %s", a, utils.PrettyPrint(a)))

		enforcement := wiz.PolicyLifecycleEnforcementInput{}

		for c, d := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf("policy_lifecycle_enforcements c: (%T) %s", c, c))
			tflog.Trace(ctx, fmt.Sprintf("policy_lifecycle_enforcements d: (%T) %s", d, utils.PrettyPrint(d)))
			switch c {
			case "deployment_lifecycle":
				enforcement.DeploymentLifecycle = d.(string)
			case "enforcement_method":
				enforcement.EnforcementMethod = d.(string)
			case "enforcement_config":
				// Handle enforcement config if provided
				if configSet, ok := d.(*schema.Set); ok && configSet.Len() > 0 {
					enforcement.EnforcementConfig = handleEnforcementConfig(ctx, configSet)
				}
			default:
				tflog.Warn(ctx, fmt.Sprintf("No valid PolicyLifecycleEnforcement case found for %s", c))
			}
		}

		enforcements = append(enforcements, enforcement)
	}

	return enforcements
}

func handleVulnerabilitiesParamsUpdate(ctx context.Context, d *schema.ResourceData) *wiz.UpdateCICDScanPolicyDiskVulnerabilitiesPatch {
	tflog.Debug(ctx, "Handling updates for CICDScanPolicyParamsVulnerabilities")
	varsType := &wiz.UpdateCICDScanPolicyDiskVulnerabilitiesPatch{}

	for _, a := range d.Get("disk_vulnerabilities_params").(*schema.Set).List() {
		tflog.Trace(ctx, fmt.Sprintf(paramsFormatDebug, a, a))
		tflog.Trace(ctx, fmt.Sprintf("b: (%T) %s", a, utils.PrettyPrint(a)))
		for c, d := range a.(map[string]interface{}) {
			tflog.Trace(ctx, fmt.Sprintf("CICDScanPolicyParamsVulnerabilities c: (%T) %s", c, c))
			tflog.Trace(ctx, fmt.Sprintf("CICDScanPolicyParamsVulnerabilities d: (%T) %s", d, utils.PrettyPrint(d)))
			switch c {
			case "ignore_unfixed":
				varsType.IgnoreUnfixed = utils.ConvertBoolToPointer(d.(bool))
			case "package_allow_list":
				varsType.PackageAllowList = utils.ConvertListToString(d.([]interface{}))
			case "package_count_threshold":
				varsType.PackageCountThreshold = d.(int)
			case "severity":
				varsType.Severity = d.(string)
			default:
				tflog.Warn(ctx, fmt.Sprintf("No valid CICDScanPolicyParamsVulnerabilities case found for %s", c))
			}
		}
	}

	return varsType
}

func resourceWizCICDScanPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diags diag.Diagnostics) {
	tflog.Info(ctx, "resourceWizCICDScanPolicyUpdate called...")

	// check the id
	if d.Id() == "" {
		return nil
	}

	// define the graphql query
	query := `mutation updateCICDScanPolicy(
	    $input: UpdateCICDScanPolicyInput
	) {
	    updateCICDScanPolicy(
	        input: $input
	    ) {
	        scanPolicy {
	            id
	        }
	    }
	}`

	// populate the graphql variables
	vars := &wiz.UpdateCICDScanPolicyInput{}
	vars.ID = d.Id()
	if d.HasChange("name") {
		tflog.Debug(ctx, fmt.Sprintf("Name has changed to %s", d.Get("name").(string)))
		vars.Patch.Name = d.Get("name").(string)
	}
	if d.HasChange("description") {
		tflog.Debug(ctx, fmt.Sprintf("Description has changed to %s", d.Get("description").(string)))
		vars.Patch.Description = d.Get("description").(string)
	}

	// Handle policy lifecycle enforcements changes
	if d.HasChange("policy_lifecycle_enforcements") {
		tflog.Debug(ctx, "PolicyLifecycleEnforcements have changed")
		enforcements := handlePolicyLifecycleEnforcementsUpdate(ctx, d)
		vars.Patch.PolicyLifecycleEnforcements = &enforcements
	}

	// we need to evaluate whether the policy type changed before setting the params
	_, diags = setPolicyType(ctx, d)

	if len(diags) > 0 {
		return diags
	}

	switch d.Get("type") {
	case "CICDScanPolicyParamsIAC":
		tflog.Debug(ctx, "Handling updates for CICDScanPolicyParamsIAC")
		vars.Patch.IACParams = handleIACParamsUpdate(ctx, d)
	case "CICDScanPolicyParamsSecrets":
		tflog.Debug(ctx, "Handling updates for CICDScanPolicyParamsSecrets")
		vars.Patch.DiskSecretsParams = handleSecretsParamsUpdate(ctx, d)
	case "CICDScanPolicyParamsVulnerabilities":
		vars.Patch.DiskVulnerabilitiesParams = handleVulnerabilitiesParamsUpdate(ctx, d)
	default:
		tflog.Warn(ctx, fmt.Sprintf("No valid case found for %s", d.Get("type")))
	}

	// process the request
	data := &UpdateCICDScanPolicy{}
	requestDiags := client.ProcessRequest(ctx, m, vars, data, query, "cicd_scan_policy", "update")
	diags = append(diags, requestDiags...)
	if len(diags) > 0 {
		return diags
	}

	return resourceWizCICDScanPolicyRead(ctx, d, m)
}

// DeleteCICDScanPolicy struct
type DeleteCICDScanPolicy struct {
	DeleteCICDScanPolicy wiz.DeleteCICDScanPolicyPayload `json:"deleteCICDScanPolicy"`
}

func resourceWizCICDScanPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diags diag.Diagnostics) {
	tflog.Info(ctx, "resourceWizCICDScanPolicyDelete called...")

	// check the id
	if d.Id() == "" {
		return nil
	}

	// define the graphql query
	query := `mutation DeleteCICDScanPolicy (
	    $input: DeleteCICDScanPolicyInput!
	) {
	    deleteCICDScanPolicy(
	        input: $input
	    ) {
	        id
	    }
	}`

	// populate the graphql variables
	vars := &wiz.DeleteCICDScanPolicyInput{}
	vars.ID = d.Id()

	// process the request
	data := &UpdateCICDScanPolicy{}
	requestDiags := client.ProcessRequest(ctx, m, vars, data, query, "cicd_scan_policy", "delete")
	diags = append(diags, requestDiags...)
	if len(diags) > 0 {
		return diags
	}

	return diags
}

func setPolicyType(ctx context.Context, d *schema.ResourceData) (string, diag.Diagnostics) {
	tflog.Debug(ctx, "setPolicyType called...")
	var diags diag.Diagnostics
	if d.Get("disk_vulnerabilities_params").(*schema.Set).Len() > 0 {
		err := d.Set("type", "CICDScanPolicyParamsVulnerabilities")
		if err != nil {
			return "", append(diags, diag.FromErr(err)...)
		}
		return "CICDScanPolicyParamsVulnerabilities", diags
	}
	if d.Get("disk_secrets_params").(*schema.Set).Len() > 0 {
		err := d.Set("type", "CICDScanPolicyParamsSecrets")
		if err != nil {
			return "", append(diags, diag.FromErr(err)...)
		}
		return "CICDScanPolicyParamsSecrets", diags
	}
	if d.Get("iac_params").(*schema.Set).Len() > 0 {
		err := d.Set("type", "CICDScanPolicyParamsIAC")
		if err != nil {
			return "", append(diags, diag.FromErr(err)...)
		}
		return "CICDScanPolicyParamsIAC", diags
	}
	return "", diags
}
