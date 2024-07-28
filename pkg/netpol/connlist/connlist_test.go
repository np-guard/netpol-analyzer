/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/stretchr/testify/require"
)

const ResourceInfosFunc = "ConnlistFromResourceInfos"
const DirPathFunc = "ConnlistFromDirPath"
const currentPkg = "connlist"
const notEmptyMsg = "expecting non-empty analysis res"

var allFormats = []string{output.TextFormat, output.JSONFormat, output.CSVFormat, output.MDFormat, output.DOTFormat}
var connlistTestedAPIS = []string{ResourceInfosFunc, DirPathFunc}

/*
interfaces to  test:
- ConnlistFromResourceInfos
- ConnlistFromDirPath
- ConnectionsListToString

*/

/*
	ConnlistFromResourceInfos:
	Examples for possible errors (non fatal) returned from this call (ResourceInfoListToK8sObjectsList):
	(1) (Warning) malformed k8s resource manifest: "in file: tests\malformed_pod_example\pod.yaml,
	YAML document is malformed: unrecognized type: int32"
	(2) (Warning) malformed k8s resource manifest: "in file: tests\malformed-pod-example-2\pod_list.json,
	 YAML document is malformed: cannot restore slice from map"
	(3) (Warning) no network policy resources found: (tests/malformed_pod_example):
	"no relevant Kubernetes network policy resources found"
	(4) (Error) no workload resources found: (tests/malformed_pod_example/) :
	"no relevant Kubernetes workload resources found"

	Examples for Log Infos that can be printed from this call:
	(1) (Info) in file: tests/bad_yamls/irrelevant_k8s_resources.yaml, skipping object with type: IngressClass

	TODO: add tests to check the Info message is added to the log

	Example for possible fatal-Errors returned from the call below: (connslistFromParsedResources)
	(1) (fatal-err) netpol-err: CIDR error (not a valid ipv4 CIDR)
	(2) additional netpol-err... (e.g. LabelSelector error), and more..
*/

/*
	ConnlistFromDirPath:
	Examples for possible errors returned from this call (GetResourceInfos):
	(1) dir does not exist: "Error: the path "tests/bad_yamls/subdir5" does not exist"
	(2) empty dir : "Error: error reading [tests/bad_yamls/subdir2/]: recognized file
	extensions are [.json .yaml .yml]"
	(3) irrelevant JSON : "GetResourceInfos error: unable to decode "tests\\onlineboutique\\connlist_output.json":
	json: cannot unmarshal array into Go value of type unstructured.detector"
	(4) bad JSON/YAML - missing kind : "Error: unable to decode "tests\\malformed-pod-example-4\\pods.json":
	 Object 'Kind' is missing in '{ ... }"
	(5) YAML doc with syntax error: "error parsing tests/document_with_syntax_error.yaml: error
	converting YAML to JSON: yaml: line 19: found character that cannot start any token"

*/

/////////////////////////////////////good path tests /////////////////////////////////////////////////////////////////////////////////

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnListFromDir(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		tt := tt
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format)
				res, _, err := pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
				require.Nil(t, err, pTest.testInfo)
				out, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
					pTest.testInfo, currentPkg)
			}
		})
	}
}

func TestConnListFromResourceInfos(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		tt := tt
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format)
				infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
				// require.Empty(t, errs, testInfo) - TODO: add info about expected errors
				// from each test here (these errors do not stop the analysis or affect the output)
				// more suitable to test this in a separate package (manifests) where  GetResourceInfosFromDirPath is implemented
				res, _, err := pTest.analyzer.ConnlistFromResourceInfos(infos)
				require.Nil(t, err, pTest.testInfo)
				out, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
					pTest.testInfo, currentPkg)
			}
		})
	}
}

//////////////////////////////////// The following tests are taken from /////////////////////////////////////
// https://github.com/kubernetes-sigs/network-policy-api/blob/main/cmd/policy-assistant/test/integration/integration_test.go

const (
	podA = `
apiVersion: v1
kind: Pod
metadata:
  name: a
  namespace: xx
  labels:
    pod: a
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - name: serve-80-tcp
      containerPort: 80
      protocol: TCP
status:
  podIPs:
  - ip: 192.168.49.2
  hostIP: 192.168.49.2`

	podB = `
apiVersion: v1
kind: Pod
metadata:
  name: b
  namespace: yy
  labels:
    pod: b
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
status:
  podIPs:
  - ip: 192.168.49.2
  hostIP: 192.168.49.2`

	podC = `
apiVersion: v1
kind: Pod
metadata:
  name: c
  namespace: zz
  labels:
    pod: c
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
status:
  podIPs:
  - ip: 192.168.49.2
  hostIP: 192.168.49.2`
)

var serve80tcp = "serve-80-tcp"

func podFromYaml(podYamlStr string) (*v1.Pod, error) {
	podObj := v1.Pod{}
	err := yaml.Unmarshal([]byte(podYamlStr), &podObj)
	if err != nil {
		return nil, err
	}
	return &podObj, nil
}

type parsedResourcesTest struct {
	name           string
	testInfo       string
	npList         []*netv1.NetworkPolicy
	anpList        []*v1alpha1.AdminNetworkPolicy
	outputFormat   string
	expectedOutput string
	resources      []parser.K8sObject
	analyzer       *ConnlistAnalyzer
}

func (test *parsedResourcesTest) initTest(podList []*v1.Pod, nsList []*v1.Namespace) {
	test.testInfo = fmt.Sprintf("test: %q, output format: %q", test.name, test.outputFormat)
	for _, ns := range nsList {
		k8sObj := parser.CreateNamespaceK8sObject(ns)
		test.resources = append(test.resources, k8sObj)
	}
	for _, pod := range podList {
		k8sObj := parser.CreatePodK8sObject(pod)
		test.resources = append(test.resources, k8sObj)
	}
	for _, np := range test.npList {
		k8sObj := parser.CreateNetwordPolicyK8sObject(np)
		test.resources = append(test.resources, k8sObj)
	}
	for _, anp := range test.anpList {
		k8sObj := parser.CreateAdminNetwordPolicyK8sObject(anp)
		test.resources = append(test.resources, k8sObj)
	}
	test.analyzer = NewConnlistAnalyzer(WithOutputFormat(test.outputFormat))
}

func TestANPConnectivityFromParsedResources(t *testing.T) {
	testList := []parsedResourcesTest{
		{
			name:         "egress port number protocol unspecified",
			outputFormat: string(output.TextFormat),
			expectedOutput: `0.0.0.0-255.255.255.255 => xx/a[Pod] : All Connections
0.0.0.0-255.255.255.255 => yy/b[Pod] : All Connections
0.0.0.0-255.255.255.255 => zz/c[Pod] : All Connections
xx/a[Pod] => 0.0.0.0-255.255.255.255 : All Connections
xx/a[Pod] => yy/b[Pod] : All but: TCP 80
xx/a[Pod] => zz/c[Pod] : All Connections
yy/b[Pod] => 0.0.0.0-255.255.255.255 : All Connections
yy/b[Pod] => xx/a[Pod] : All Connections
yy/b[Pod] => zz/c[Pod] : All Connections
zz/c[Pod] => 0.0.0.0-255.255.255.255 : All Connections
zz/c[Pod] => xx/a[Pod] : All Connections
zz/c[Pod] => yy/b[Pod] : All Connections`,
			anpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "xx"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "yy"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port: 80,
										},
									},
								}),
							},
						},
					},
				},
			},
		},
		{
			name:         "ingress port number protocol unspecified",
			outputFormat: string(output.TextFormat),
			expectedOutput: `0.0.0.0-255.255.255.255 => xx/a[Pod] : All Connections
0.0.0.0-255.255.255.255 => yy/b[Pod] : All Connections
0.0.0.0-255.255.255.255 => zz/c[Pod] : All Connections
xx/a[Pod] => 0.0.0.0-255.255.255.255 : All Connections
xx/a[Pod] => yy/b[Pod] : All Connections
xx/a[Pod] => zz/c[Pod] : All Connections
yy/b[Pod] => 0.0.0.0-255.255.255.255 : All Connections
yy/b[Pod] => xx/a[Pod] : All but: TCP 80
yy/b[Pod] => zz/c[Pod] : All Connections
zz/c[Pod] => 0.0.0.0-255.255.255.255 : All Connections
zz/c[Pod] => xx/a[Pod] : All Connections
zz/c[Pod] => yy/b[Pod] : All Connections`,
			anpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "xx"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "yy"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port: 80,
										},
									},
								}),
							},
						},
					},
				},
			},
		},
		{
			name:         "ingress named port",
			outputFormat: string(output.TextFormat),
			expectedOutput: `0.0.0.0-255.255.255.255 => xx/a[Pod] : All Connections
0.0.0.0-255.255.255.255 => yy/b[Pod] : All Connections
0.0.0.0-255.255.255.255 => zz/c[Pod] : All Connections
xx/a[Pod] => 0.0.0.0-255.255.255.255 : All Connections
xx/a[Pod] => yy/b[Pod] : All Connections
xx/a[Pod] => zz/c[Pod] : All Connections
yy/b[Pod] => 0.0.0.0-255.255.255.255 : All Connections
yy/b[Pod] => xx/a[Pod] : All but: TCP 80
yy/b[Pod] => zz/c[Pod] : All Connections
zz/c[Pod] => 0.0.0.0-255.255.255.255 : All Connections
zz/c[Pod] => xx/a[Pod] : All Connections
zz/c[Pod] => yy/b[Pod] : All Connections`,
			anpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "xx"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "yy"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										NamedPort: &serve80tcp,
									},
								}),
							},
						},
					},
				},
			},
		},
	}

	podList := []*v1.Pod{}
	podsYamlList := []string{podA, podB, podC}
	for _, podYaml := range podsYamlList {
		podObj, err := podFromYaml(podYaml)
		if err != nil {
			t.Fatalf("error getting pod object")
		}
		podList = append(podList, podObj)
	}
	nsList := []*v1.Namespace{}
	nsList = append(nsList, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "xx", Labels: map[string]string{"ns": "xx"}}},
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "yy", Labels: map[string]string{"ns": "yy"}}})

	for _, test := range testList {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// t.Parallel()
			test.initTest(podList, nsList)
			res, _, err := test.analyzer.connslistFromParsedResources(test.resources)
			require.Nil(t, err, test.testInfo)
			out, err := test.analyzer.ConnectionsListToString(res)
			fmt.Printf("The result of %s:\n%s\n\n", test.testInfo, out)
			require.Nil(t, err, test.testInfo)
			require.Equal(t, test.expectedOutput, out,
				"output mismatch for %s, actual output: %q vs expected output: %q",
				test.testInfo, out, test.expectedOutput)
		})
	}
}

/////////////////////////////////////bad path tests /////////////////////////////////////////////////////////////////////////////////

// fatal errors common for both interfaces (ConnlistFromDirPath & ConnlistFromResourceInfos)
//--------------------------------------------------------------------------------------------

func TestConnlistAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
	}{
		// invalid netpols batch
		{
			name:             "Input_dir_has_netpol_with_invalid_cidr_should_return_fatal_error_of_invalid_CIDR_address",
			dirName:          filepath.Join("bad_netpols", "subdir1"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.CidrErrTitle, netpolerrors.InvalidCIDRAddr),
		},
		{
			name:             "Input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
			dirName:          filepath.Join("bad_netpols", "subdir2"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.SelectorErrTitle, netpolerrors.InvalidKeyVal),
		},
		{
			name:             "Input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir3"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.RulePeerErrTitle, netpolerrors.CombinedRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir4"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.RulePeerErrTitle, netpolerrors.EmptyRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
			dirName:          filepath.Join("bad_netpols", "subdir6"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.NamedPortErrTitle, netpolerrors.ConvertNamedPortErrStr),
		},
		/*// input dir does not exist
		{
			name:             "Input_dir_does_not_exist_should_return_fatal_error_accessing_directory",
			dirName:          filepath.Join("bad_yamls", "subdir3"),
			errorStrContains: "does not exist", // TODO: actual msg: "the path ... does not exist"
		},*/
		// pods list issue - pods with same owner but different labels
		{
			name:             "Input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
			dirName:          "semanticDiff-same-topologies-illegal-podlist",
			errorStrContains: netpolerrors.NotSupportedPodResourcesErrorStr("demo/cog-agents"),
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, "")
				testFatalErr(t, connsRes, peersRes, err, tt.name, tt.errorStrContains, analyzer)
			}
		})
	}
}

func testFatalErr(t *testing.T,
	connsRes []Peer2PeerConnection,
	peersRes []Peer,
	err error,
	testName, errStr string,
	analyzer *ConnlistAnalyzer) {
	require.Empty(t, connsRes, testName)
	require.Empty(t, peersRes, testName)
	testutils.CheckErrorContainment(t, testName, errStr, err.Error())
	require.Equal(t, len(analyzer.errors), 1)
	testutils.CheckErrorContainment(t, testName, errStr, analyzer.errors[0].Error().Error())
}

func getAnalysisResFromAPI(apiName, dirName, focusWorkload string) (
	analyzer *ConnlistAnalyzer, connsRes []Peer2PeerConnection, peersRes []Peer, err error) {
	pTest := prepareTest(dirName, focusWorkload, output.DefaultFormat)
	switch apiName {
	case ResourceInfosFunc:
		infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
		connsRes, peersRes, err = pTest.analyzer.ConnlistFromResourceInfos(infos)
	case DirPathFunc:
		connsRes, peersRes, err = pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
	}
	return pTest.analyzer, connsRes, peersRes, err
}

// severe errors and warnings, common for both interfaces (ConnlistFromDirPath & ConnlistFromResourceInfos)
//--------------------------------------------------------------------------------------------

// TODO: test stopOnErr here?

//nolint:gocritic //temporary commented-out code
func TestConnlistAnalyzeSevereErrorsAndWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		dirName             string
		firstErrStrContains string
		emptyRes            bool
		focusWorkload       string
		/*expectedErrNumWithoutStopOnErr int
		expectedErrNumWithStopOnErr    int*/
	}{

		{
			name:                "input_file_has_no_relevant_k8s_resources",
			dirName:             filepath.Join("bad_yamls", "irrelevant_k8s_resources.yaml"),
			firstErrStrContains: netpolerrors.NoK8sWorkloadResourcesFoundErrorStr,
			emptyRes:            true,
		},
		{
			name:                "no_network_policy_resources_warning",
			dirName:             "no_netpols_dir",
			firstErrStrContains: netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr,
			emptyRes:            false,
		},
		/*
			$ ./bin/k8snetpolicy list --dirpath tests/malformed_pod_example/
			2023/11/02 08:56:16 : err : in file: tests\malformed_pod_example\pod.yaml YAML document is malformed:
			 error for resource with kind: Pod , name: nginx , :  unrecognized type: int32
			2023/11/02 08:56:16 : no relevant Kubernetes workload resources found
			2023/11/02 08:56:16 no relevant Kubernetes network policy resources found


		*/
		{
			name:                "malformed_yaml_unrecognized_type_int32",
			dirName:             "malformed_pod_example",
			firstErrStrContains: netpolerrors.UnrecognizedValType, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            true,
		},
		{
			name:                "malformed_yaml_cannot_restore_slice_from_map",
			dirName:             "malformed-pod-example-2",
			firstErrStrContains: netpolerrors.SliceFromMapErr, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            false,
		},
		{
			name:                "input_dir_with_focusworkload_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "abcd",
			firstErrStrContains: netpolerrors.WorkloadDoesNotExistErrStr("abcd"),
			emptyRes:            true,
		},
		{
			name:                "input_dir_with_focusworkload_ns_and_name_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "default/abcd",
			firstErrStrContains: netpolerrors.WorkloadDoesNotExistErrStr("default/abcd"),
			emptyRes:            true,
		},

		/*{
			// this error issued by builder
			name:                           "input_file_has_malformed_yaml_doc_should_return_severe_error",
			dirName:                        "document_with_syntax_error",
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    1,
			firstErrStrContains:            "found character that cannot start any token", //"YAML document is malformed",
		},
		{
			// this error issued by builder
			name:                           "input_file_is_not_a_valid_k8s_resource_should_return_severe_error",
			dirName:                        filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			expectedErrNumWithoutStopOnErr: 3,                  //2,
			expectedErrNumWithStopOnErr:    2,                  // an error and a warning
			firstErrStrContains:            "unable to decode", //"Yaml document is not a K8s resource",
		},*/
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, tt.focusWorkload)
				require.Nil(t, err, tt.name)
				if tt.emptyRes {
					require.Empty(t, connsRes, tt.name)
					require.Empty(t, peersRes, tt.name)
				} else {
					require.NotEmpty(t, connsRes, tt.name)
					require.NotEmpty(t, peersRes, tt.name)
				}
				testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, analyzer.errors[0].Error().Error())
			}

			/*analyzerOpts1 := []ConnlistAnalyzerOption{}
			analyzerOpts2 := []ConnlistAnalyzerOption{WithStopOnError()}
			// severe is not fatal, thus not returned
			// first analyzer:
			analyzer, _, err1 := getConnlistFromDirPathRes(analyzerOpts1, tt.dirName)
			resErrors1 := analyzer.Errors()
			require.Nil(t, err1, "test: %q", tt.name)
			require.Equal(t, tt.expectedErrNumWithoutStopOnErr, len(resErrors1), "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, resErrors1[0].Error().Error(), true)
			// second analyzer (with stopOnError):

			analyzerWithStopOnError, res, err2 := getConnlistFromDirPathRes(analyzerOpts2, tt.dirName)
			resErrors2 := analyzerWithStopOnError.Errors()
			require.Nil(t, err2, "test: %q", tt.name)
			require.Empty(t, res, "test: %q", tt.name) // the run stopped on first severe error, no result computed
			require.Equal(t, tt.expectedErrNumWithStopOnErr, len(resErrors2), "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, resErrors2[0].Error().Error(), true)*/
		})
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test errs/warnings unique for ConnlistFromDirPath only (issued by the resources builder)
// ----------------------------------------------------------------------------------------------

func TestFatalErrorsConnlistFromDirPathOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
	}{
		{
			name:             "dir_does_not_exist_err",
			dirName:          "ttt",
			errorStrContains: netpolerrors.PathNotExistErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "empty_dir_with_no_yamls_or_json_files",
			dirName:          filepath.Join("bad_yamls", "subdir2"),
			errorStrContains: netpolerrors.UnknownFileExtensionErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "bad_JSON_missing_kind", // this err is fatal here only because dir has no other resources
			dirName:          "malformed-pod-example-4",
			errorStrContains: netpolerrors.MissingObjectErr, // kind is missing in pod json, netpolerrors.ErrGettingResInfoFromDir
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, "")
			testFatalErr(t, connsRes, peersRes, err, tt.name, tt.errorStrContains, analyzer)
		})
	}
}

func TestErrorsAndWarningsConnlistFromDirPathOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
		emptyRes         bool
		focusWorkload    string
	}{
		{
			name:             "irrelevant_JSON_file_unable_to_decode",
			dirName:          "onlineboutique",
			errorStrContains: netpolerrors.UnmarshalErr, // netpolerrors.FailedReadingFileErrorStr
			emptyRes:         false,
		},
		{
			name:             "YAML_syntax_err",
			dirName:          "malformed-pod-example-5",
			errorStrContains: netpolerrors.WrongStartCharacterErr, // netpolerrors.FailedReadingFileErrorStr
			emptyRes:         false,
			// TODO: this test has another error (missing kind in another file), add this to the testing functionality
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, tt.focusWorkload)
			require.Nil(t, err, tt.name)
			if tt.emptyRes {
				require.Empty(t, connsRes, tt.name)
				require.Empty(t, peersRes, tt.name)
			} else {
				require.NotEmpty(t, connsRes, tt.name)
				require.NotEmpty(t, peersRes, tt.name)
			}
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, analyzer.errors[0].Error().Error())
		})
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

// TestNotContainedOutputLines tests output for non-expected lines to be contained
func TestNotContainedOutputLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                 string
		dirName              string
		focusWorkload        string
		expectedResultLen    int
		extractedLineExample string
	}{
		{
			//	we don't expect to see connections from a workload to itself,
			// even though the focus workload has different replicas which may connect to each other.
			name:                 "connlist_does_not_contain_connections_from_focus_workload_to_itself",
			dirName:              "ipblockstest",
			focusWorkload:        "calico-node",
			expectedResultLen:    49,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
		{
			name:                 "connlist_of_dir_does_not_contain_any_line_of_connections_from_workload_to_itself",
			dirName:              "ipblockstest",
			expectedResultLen:    602,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := appendFocusWorkloadOptIfRequired(tt.focusWorkload)
			analyzer, res, err := getConnlistFromDirPathRes(analyzerOpts, tt.dirName)
			require.Len(t, res, tt.expectedResultLen, "test: %q", tt.name)
			require.Nil(t, err, "test: %q", tt.name)
			out, err := analyzer.ConnectionsListToString(res)
			require.Nil(t, err, "test: %q", tt.name)
			require.NotContains(t, out, tt.extractedLineExample, "test: %q, output should not contain %q", tt.name, tt.extractedLineExample)
		})
	}
}

// helping func - creates ConnlistAnalyzer with desired opts and returns the analyzer with connlist from provided directory
func getConnlistFromDirPathRes(opts []ConnlistAnalyzerOption, dirName string) (*ConnlistAnalyzer, []Peer2PeerConnection, error) {
	analyzer := NewConnlistAnalyzer(opts...)
	res, _, err := analyzer.ConnlistFromDirPath(testutils.GetTestDirPath(dirName))
	return analyzer, res, err
}

// helping func - if focus workload is not empty append it to ConnlistAnalyzerOption list
func appendFocusWorkloadOptIfRequired(focusWorkload string) []ConnlistAnalyzerOption {
	analyzerOptions := []ConnlistAnalyzerOption{}
	if focusWorkload != "" {
		analyzerOptions = append(analyzerOptions, WithFocusWorkload(focusWorkload))
	}
	return analyzerOptions
}

type preparedTest struct {
	testName               string
	testInfo               string
	dirPath                string
	expectedOutputFileName string
	analyzer               *ConnlistAnalyzer
}

func prepareTest(dirName, focusWorkload, format string) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testutils.ConnlistTestNameByTestArgs(dirName, focusWorkload, format)
	res.testInfo = fmt.Sprintf("test: %q, output format: %q", res.testName, format)
	res.analyzer = NewConnlistAnalyzer(WithOutputFormat(format), WithFocusWorkload(focusWorkload))
	res.dirPath = testutils.GetTestDirPath(dirName)
	return res
}

// fatal errors for interface ConnectionsListToString
//--------------------------------------------------------------------------------------------

// TestConnlistOutputFatalErrors tests fatal errors returned while writing the connlist to string in given output format
func TestConnlistOutputFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		format           string
		errorStrContains string
	}{
		{
			name:             "giving_unsupported_output_format_option_should_return_fatal_error",
			dirName:          "onlineboutique",
			format:           "docx",
			errorStrContains: netpolerrors.FormatNotSupportedErrStr("docx"),
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			preparedTest := prepareTest(tt.dirName, "", tt.format)
			connsRes, peersRes, err := preparedTest.analyzer.ConnlistFromDirPath(preparedTest.dirPath)

			require.Nil(t, err, tt.name)
			// "unable to decode ... connlist_output.json"
			require.Equal(t, len(preparedTest.analyzer.errors), 1, "expecting error since builder not able to parse connlist_output.json")
			require.NotEmpty(t, connsRes, notEmptyMsg)
			require.NotEmpty(t, peersRes, notEmptyMsg)

			out, err := preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, out, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err.Error())

			// re-run the test with new analyzer (to clear the analyzer.errors array )
			preparedTest = prepareTest(tt.dirName, "", tt.format)
			infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{preparedTest.dirPath}, true, false)
			connsRes2, peersRes2, err2 := preparedTest.analyzer.ConnlistFromResourceInfos(infos)

			require.Nil(t, err2, tt.name)
			require.Empty(t, preparedTest.analyzer.errors, "expecting no errors from ConnlistFromResourceInfos")
			require.NotEmpty(t, connsRes2, notEmptyMsg)
			require.NotEmpty(t, peersRes2, notEmptyMsg)

			out, err2 = preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, out, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err2.Error())
		})
	}
}

var goodPathTests = []struct {
	testDirName   string
	outputFormats []string
	focusWorkload string
}{
	{
		testDirName:   "ipblockstest",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "onlineboutique",
		outputFormats: []string{output.JSONFormat, output.MDFormat, output.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		outputFormats: []string{output.CSVFormat, output.DOTFormat, output.TextFormat},
	},
	{
		testDirName:   "minikube_resources",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "online_boutique_workloads_no_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "core_pods_without_host_ip",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs_security_frontend_demos",
		outputFormats: allFormats,
	},
	{
		testDirName:   "demo_app_with_routes_and_ingress",
		outputFormats: allFormats,
	},
	{
		testDirName:   "k8s_ingress_test",
		outputFormats: allFormats,
	},
	{
		testDirName:   "multiple_ingress_objects_with_different_ports",
		outputFormats: allFormats,
	},
	{
		testDirName:   "one_ingress_multiple_ports",
		outputFormats: allFormats,
	},
	{
		testDirName:   "one_ingress_multiple_services",
		outputFormats: allFormats,
	},
	{
		testDirName:   "acs-security-demos",
		outputFormats: allFormats,
	},
	{
		testDirName:   "acs-security-demos-with-netpol-list",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "netpol-analysis-example-minimal",
		outputFormats: allFormats,
	},
	{
		testDirName:   "with_end_port_example",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "with_end_port_example_new",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "new_online_boutique",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "new_online_boutique_synthesis",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_4",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "minimal_test_in_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-no-policy",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-policy-a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_4",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a-with-ipblock",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b-with-ipblock",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		focusWorkload: "emailservice",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "k8s_ingress_test",
		focusWorkload: "details-v1-79f774bdb9",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "backend/recommendation",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "asset-cache",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "frontend/asset-cache",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "ingress-controller",
		outputFormats: []string{output.TextFormat},
	},
	// tests with adminNetworkPolicy
	{
		testDirName:   "anp_test1_deny_traffic_at_cluster_level",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "anp_test2_allow_traffic_at_cluster_level",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "anp_test3_pass_traffic",
		outputFormats: []string{output.TextFormat},
	},
	{
		// Should Deny traffic from slytherin to gryffindor and
		// Deny traffic to slytherin from gryffindor respecting ANP with priority 50, ignoring ANP with priority 60
		testDirName:   "anp_test_4",
		outputFormats: allFormats,
	},
	{
		// Should support a pass-egress to slytherin from gryffindor for ANP and respect the match for network policy
		// And Dney ingress from slytherin to gryffindor - respecting the ANP ingress rule
		testDirName:   "anp_test_5",
		outputFormats: allFormats,
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_6",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_6 but with swaps, so we expect some different results
		testDirName:   "anp_test_6_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_7",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_7 but with swaps, so we expect some different results
		testDirName:   "anp_test_7_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_8",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_8 but with swaps, so we expect some different results
		testDirName:   "anp_test_8_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected, with both ingress and egress
		testDirName:   "anp_test_9",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_9 but with swaps, so we expect some different results
		testDirName:   "anp_test_9_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_10",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_10 but with swaps, so we expect some different results
		testDirName:   "anp_test_10_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_11",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_11 but with swaps, so we expect some different results
		testDirName:   "anp_test_11_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_12",
		outputFormats: allFormats,
	},
	{
		// rules are similar to the ones from anp_test_12 but with swaps, so we expect some different results
		testDirName:   "anp_test_12_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// test with two ANPs selecting same subject (one is an ingress ANP the other is egress ANP)
		testDirName:   "anp_test_combining_test6_and_test10",
		outputFormats: []string{output.TextFormat},
	},
	{
		// test with multiple ANPs
		testDirName:   "anp_test_multiple_anps",
		outputFormats: allFormats,
	},
}
