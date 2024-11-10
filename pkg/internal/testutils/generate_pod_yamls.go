/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package testutils

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/projectpath"
)

// a test util for eval command-line; generating a new temporary directory with pod files to be used for testing.
// eval command supports only test directories with Pod objects.
// some of our testing directories are containing other Workload types in the manifests; in order to be able to test
// eval command on those dirs (in unit-testing); this file funcs are used.
// we copy the test-die into a new temporary dir, and generate into the tempDir :
// Pod yaml files for given src and dst peers from their workload resources

const (
	tmpPattern = "temp-*"
	exeMode    = 0o777
)

var TmpDir = filepath.Join(projectpath.Root, "temp") // cleaned up after the test is done

// GenerateTempDirWithPods generates new temporary dir that copies origDir and adds yaml files of Pod kind
// matching the input workload resources of the src and dst
// the function returns the path of the generated temp dir.
func GenerateTempDirWithPods(origDir, srcName, srcNs, dstName, dstNs string) (string, error) {
	// create the TmpDir path if does not exist
	if _, err := os.Stat(TmpDir); os.IsNotExist(err) {
		osErr := os.Mkdir(TmpDir, exeMode)
		if osErr != nil {
			return "", osErr
		}
	}
	// making temp directory in the temp path
	testTmpDir, err := os.MkdirTemp(TmpDir, tmpPattern)
	if err != nil {
		return "", err
	}
	// copy orig dir into the temp dir
	err = copyDir(origDir, testTmpDir, srcName, srcNs, dstName, dstNs)
	return testTmpDir, err
}

// copyDir copies files of network-policies from origDir into tempDir
// and generates into the tempDir : Pod yaml files for given src and dst peers from their workload resources
// in the origDir
func copyDir(origDir, tempDir, srcName, srcNs, dstName, dstNs string) error {
	return filepath.Walk(origDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() { // nothing to do
			return nil
		}
		origFile := filepath.Join(origDir, info.Name())
		tempFile := filepath.Join(tempDir, info.Name())
		// if the file contains workload with given srcName or dstName : get the workload object and
		// generate matching pod yaml file in the temp dir
		// this is needed since we need also a copy of the workload labels which may be used in the netpols rules

		// find src and get its labels
		srcLabels, err := checkFileContainsInputWorkloadAndGetItsLabels(origFile, srcName, srcNs)
		if err != nil {
			return err
		}
		if srcLabels != nil { // nil means the src was not found in that file
			err = generatePodYaml(tempDir, srcName, srcNs, srcLabels)
			if err != nil {
				return err
			}
		}

		// find dst and get its labels
		dstLabels, err := checkFileContainsInputWorkloadAndGetItsLabels(origFile, dstName, dstNs)
		if err != nil {
			return err
		}
		if dstLabels != nil { // nil means the dst was not found in that file
			err = generatePodYaml(tempDir, dstName, dstNs, dstLabels)
			if err != nil {
				return err
			}
		}
		// copy the orig file (having objects with kinds other than ns, pod, netpols will not affect the result
		// since it will not be parsed with the eval command)
		return copyFile(origFile, tempFile)
	})
}

// PodInfo contains metadata of the pod so we can :
// 1. extract relevant workload from input resources
// 2. generate relevant pod template
type PodInfo struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace,omitempty"`
	Labels    map[string]string `yaml:"labels,omitempty"`
}

// workloadMetadata the yaml is unmarshal to workload metadata struct which is the only interesting part for our goals
type WorkloadMetadata struct {
	Metadata PodInfo `yaml:"metadata"`
}

// checkFileContainsInputWorkloadAndGetItsLabels gets yaml contents and checks if it contains a workload object with the
// given name and namespace
// note that this assumes that if the object name and namespace matches the input, it is the workload object
// since our tests-dirs contain unique names for workloads (different than policies names)
// @todo : verify the kind is of a workload type too
func checkFileContainsInputWorkloadAndGetItsLabels(origFile, podName, podNs string) (map[string]string, error) {
	fileContents, err := os.ReadFile(origFile)
	if err != nil {
		return nil, err
	}
	// Splitting the YAML into multiple documents
	docs := splitYamlDocs(fileContents)

	// we are interested in Metadata of the workload only.
	// Iterate through objects to find the matching one
	for _, doc := range docs {
		var obj WorkloadMetadata
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return nil, err
		}
		if obj.Metadata.Name == podName && (obj.Metadata.Namespace == podNs ||
			(obj.Metadata.Namespace == "" && podNs == metav1.NamespaceDefault)) {
			if obj.Metadata.Labels == nil {
				return map[string]string{}, nil
			}
			return obj.Metadata.Labels, nil
		}
	}
	return nil, nil
}

const yamlSep = "---"

// splitYamlDocs splits a YAML file into separate documents.
// It returns a slice of byte slices, where each byte slice represents a YAML document.
func splitYamlDocs(data []byte) (docs [][]byte) {
	// Split on YAML document separator
	for _, docYAML := range bytes.Split(data, []byte(yamlSep)) {
		if len(bytes.TrimSpace(docYAML)) == 0 {
			continue
		}
		docs = append(docs, docYAML)
	}
	return docs
}

// copyFile copies origFile to tempFile
func copyFile(origFile, tempFile string) error {
	contents, err := os.ReadFile(origFile)
	if err != nil {
		return err
	}
	err = os.WriteFile(tempFile, contents, exeMode)
	return err
}

const podYamlTemplate = `apiVersion: v1
kind: Pod
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
  labels:
    {{- range $key, $value := .Labels }}
    {{ $key }}: {{ $value }}
    {{- end }}
spec:
  containers:
  - name: container-1
    image: nginx:latest
`

const yamlSuffix = ".yaml"

// generatePodYaml generates a YAML file for a given pod data.
func generatePodYaml(dirName, podName, podNs string, labels map[string]string) error {
	pod := PodInfo{Name: podName, Namespace: podNs, Labels: labels}
	fileName := podNs + "_" + podName + yamlSuffix
	podFile := filepath.Join(dirName, fileName)
	// write the pod template using the pod data
	podTmpl, err := template.New("pod").Parse(podYamlTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := podTmpl.Execute(&buf, pod); err != nil {
		return err
	}
	// write to file
	return os.WriteFile(podFile, buf.Bytes(), exeMode)
}
