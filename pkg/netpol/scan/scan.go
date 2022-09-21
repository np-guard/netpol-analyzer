package scan

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

// K8sObject holds a an object kind and a pointer of the relevant object
type K8sObject struct {
	Kind          string
	Namespace     *v1.Namespace
	Pod           *v1.Pod
	Networkpolicy *netv1.NetworkPolicy
	Replicaset    *appsv1.ReplicaSet
}

// FilesToObjectsList returns a list of K8sObject parsed from yaml files in the input dir path
func FilesToObjectsList(path string) ([]K8sObject, error) {
	res := []K8sObject{}
	parsedObjects := getK8sDeploymentResources(&path)
	for _, obj := range parsedObjects {
		for _, o := range obj.deployObjects {
			kind := o.groupKind
			fmt.Printf("%v", kind)
			if kind == pod || kind == networkpolicy || kind == namespace || kind == list {
				res1, err := scanK8sDeployObject(kind, o.runtimeObject)
				if err == nil {
					res = append(res, res1...)
				} else {
					return res, err
				}
			}
		}
	}
	return res, nil
}

const (
	pod                   string = "Pod"
	replicaSet            string = "ReplicaSet"
	replicationController string = "ReplicationController"
	deployment            string = "Deployment"
	statefulset           string = "StatefulSet"
	daemonset             string = "DaemonSet"
	job                   string = "Job"
	cronJob               string = "CronJob"
	service               string = "Service"
	configmap             string = "ConfigMap"
	networkpolicy         string = "NetworkPolicy"
	namespace             string = "Namespace"
	list                  string = "List"
)

const yamlParseBufferSize = 200

type deployObject struct {
	groupKind     string
	runtimeObject []byte
}

type parsedK8sObjects struct {
	manifestFilepath string
	deployObjects    []deployObject
}

func getK8sDeploymentResources(repoDir *string) []parsedK8sObjects {
	manifestFiles := searchDeploymentManifests(repoDir)
	if len(manifestFiles) == 0 {
		return nil
	}
	parsedObjs := []parsedK8sObjects{}
	for _, mfp := range manifestFiles {
		filebuf, err := os.ReadFile(mfp)
		if err != nil {
			continue
		}
		p := parsedK8sObjects{}
		p.manifestFilepath = mfp
		if pathSplit := strings.Split(mfp, *repoDir); len(pathSplit) > 1 {
			p.manifestFilepath = pathSplit[1]
		}
		p.deployObjects = parseK8sYaml(filebuf)
		parsedObjs = append(parsedObjs, p)
	}
	return parsedObjs
}

func searchDeploymentManifests(repoDir *string) []string {
	yamls := []string{}
	err := filepath.WalkDir(*repoDir, func(path string, f os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if f != nil && !f.IsDir() {
			r, err := regexp.MatchString(`^.*\.y(a)?ml$`, f.Name())
			if err == nil && r {
				yamls = append(yamls, path)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error: Error in searching for manifests: %v", err)
	}
	return yamls
}

func parseList(objDataBuf []byte) []K8sObject {
	r := bytes.NewReader(objDataBuf)
	res := []K8sObject{}
	if r == nil {
		return res
	}
	podsList := v1.PodList{}
	nsList := v1.NamespaceList{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&podsList)
	// currently supporting list of pods or namespaces
	if err == nil && len(podsList.Items) > 0 && podsList.Items[0].TypeMeta.Kind == pod {
		for i := range podsList.Items {
			res = append(res, K8sObject{Pod: &podsList.Items[i], Kind: pod})
		}
		return res
	}
	r = bytes.NewReader(objDataBuf)
	err = yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&nsList)
	if err == nil && len(nsList.Items) > 0 && nsList.Items[0].TypeMeta.Kind == namespace {
		for i := range nsList.Items {
			res = append(res, K8sObject{Namespace: &nsList.Items[i], Kind: namespace})
		}
		return res
	}
	return res
}

func parsePod(r io.Reader) *v1.Pod {
	if r == nil {
		return nil
	}
	rc := v1.Pod{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseNamespace(r io.Reader) *v1.Namespace {
	if r == nil {
		return nil
	}
	rc := v1.Namespace{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseNetworkPolicy(r io.Reader) *netv1.NetworkPolicy {
	if r == nil {
		return nil
	}
	rc := netv1.NetworkPolicy{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseReplicaSet(r io.Reader) *appsv1.ReplicaSet {
	if r == nil {
		return nil
	}
	rc := appsv1.ReplicaSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func scanK8sDeployObject(kind string, objDataBuf []byte) ([]K8sObject, error) {
	res := []K8sObject{}

	switch kind {
	case "Pod":
		obj := parsePod(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Pod: obj, Kind: kind})
	case "ReplicaSet":
		obj := parseReplicaSet(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Replicaset: obj, Kind: kind})
	case "NetworkPolicy":
		obj := parseNetworkPolicy(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Networkpolicy: obj, Kind: kind})
	case "Namespace":
		obj := parseNamespace(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Namespace: obj, Kind: kind})
	case "List":
		obj := parseList(objDataBuf)
		res = obj
	default:
		return res, fmt.Errorf("unsupported object type: `%s`", kind)
	}
	return res, nil
}

func splitByYamlDocuments(data []byte) []string {
	decoder := yamlv3.NewDecoder(bytes.NewBuffer(data))
	documents := []string{}
	for {
		var doc map[interface{}]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
		}
		if len(doc) > 0 {
			out, _ := yamlv3.Marshal(doc)
			documents = append(documents, string(out))
		}
	}
	return documents
}

func parseK8sYaml(fileR []byte) []deployObject {
	dObjs := []deployObject{}
	acceptedK8sTypes := regexp.MustCompile(fmt.Sprintf("(%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s)",
		pod, replicaSet, replicationController, deployment, daemonset, statefulset, job, cronJob,
		service, configmap, networkpolicy, namespace, list))
	sepYamlfiles := splitByYamlDocuments(fileR)
	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}
		decode := scheme.Codecs.UniversalDeserializer().Decode
		_, groupVersionKind, err := decode([]byte(f), nil, nil)
		if err != nil {
			continue
		}
		if !acceptedK8sTypes.MatchString(groupVersionKind.Kind) {
			fmt.Printf("Skipping object with type: %v", groupVersionKind.Kind)
		} else {
			d := deployObject{}
			d.groupKind = groupVersionKind.Kind
			d.runtimeObject = []byte(f)
			dObjs = append(dObjs, d)
		}
	}
	return dObjs
}

/*
func parseReplicationController(r io.Reader) *v1.ReplicationController {
	if r == nil {
		return nil
	}
	rc := v1.ReplicationController{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseDaemonSet(r io.Reader) *appsv1.DaemonSet {
	if r == nil {
		return nil
	}
	rc := appsv1.DaemonSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseStatefulSet(r io.Reader) *appsv1.StatefulSet {
	if r == nil {
		return nil
	}
	rc := appsv1.StatefulSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseJob(r io.Reader) *batchv1.Job {
	if r == nil {
		return nil
	}
	rc := batchv1.Job{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseService(r io.Reader) *v1.Service {
	if r == nil {
		return nil
	}
	rc := v1.Service{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func parseDeployment(r io.Reader) *appsv1.Deployment {
	if r == nil {
		return nil
	}
	rc := appsv1.Deployment{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

// exists Check whether a file with a given path exists
func exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
*/
