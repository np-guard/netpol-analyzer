package scan

import (
	"os"
	"path/filepath"
	"testing"
)

const podList = `
apiVersion: v1
items:
- apiVersion: v1
  kind: Pod
  metadata:
    creationTimestamp: "2022-08-01T17:05:22Z"
    generateName: adservice-77d5cd745d-
    labels:
      app: adservice
      pod-template-hash: 77d5cd745d
    name: adservice-77d5cd745d-t8mx4
    namespace: default
    ownerReferences:
    - apiVersion: apps/v1
      blockOwnerDeletion: true
      controller: true
      kind: ReplicaSet
      name: adservice-77d5cd745d
      uid: de20939b-c550-4dea-943d-57140c16d9e4
    resourceVersion: "1632"
    uid: 4c85f10a-15b3-4a57-bd57-c3f05240068c
  spec:
    containers:
    - env:
      - name: PORT
        value: "9555"
      - name: DISABLE_STATS
        value: "1"
      imagePullPolicy: IfNotPresent
      livenessProbe:
        exec:
          command:
          - /bin/grpc_health_probe
          - -addr=:9555
        failureThreshold: 3
        initialDelaySeconds: 20
        periodSeconds: 15
        successThreshold: 1
        timeoutSeconds: 1
      name: server
      ports:
      - containerPort: 9555
        protocol: TCP
      readinessProbe:
        exec:
          command:
          - /bin/grpc_health_probe
          - -addr=:9555
        failureThreshold: 3
        initialDelaySeconds: 20
        periodSeconds: 15
        successThreshold: 1
        timeoutSeconds: 1
      resources:
        limits:
          cpu: 300m
          memory: 300Mi
        requests:
          cpu: 200m
          memory: 180Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
    dnsPolicy: ClusterFirst
    enableServiceLinks: true
    nodeName: minikube
    preemptionPolicy: PreemptLowerPriority
    priority: 0
    restartPolicy: Always
    schedulerName: default-scheduler
    securityContext: {}
    serviceAccount: default
    serviceAccountName: default
    terminationGracePeriodSeconds: 5
  status:
    hostIP: 192.168.49.2
kind: List
metadata:
    resourceVersion: ""
    selfLink: ""`

func TestParseList(t *testing.T) {
	testName := "TestParseList"
	res := parseList([]byte(podList))
	if len(res) != 1 {
		t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", testName, len(res))
	}
}

func TestFilesToObjectsList1(t *testing.T) {
	testName := "onlineboutique_workloads"
	path := filepath.Join(getTestsDir(), testName)
	res, err := FilesToObjectsList(path, filepath.WalkDir)
	if err != nil {
		t.Fatalf("Test %s: TestFilesToObjectsList err: %v", testName, err)
	}
	if len(res) != 28 {
		t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", testName, len(res))
	}
}

func TestFilesToObjectsList2(t *testing.T) {
	testName := "ipblockstest"
	path := filepath.Join(getTestsDir(), testName)
	res, err := FilesToObjectsList(path, filepath.WalkDir)
	if err != nil {
		t.Fatalf("Test %s: TestFilesToObjectsList err: %v", testName, err)
	}
	if len(res) != 38 {
		t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", testName, len(res))
	}
}

func TestGetYAMLDocumentsFromPath(t *testing.T) {
	testName := "ipblockstest"
	path := filepath.Join(getTestsDir(), testName)
	res := GetYAMLDocumentsFromPath(path, filepath.WalkDir)
	if len(res) != 3 {
		t.Fatalf("Test %s: unexpected len of yaml files list: %d", testName, len(res))
	}
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}
