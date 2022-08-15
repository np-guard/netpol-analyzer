package eval

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

type K8sObject struct {
	kind          string
	namespace     *v1.Namespace
	pod           *v1.Pod
	networkpolicy *netv1.NetworkPolicy
	replicaset    *appsv1.ReplicaSet
}

const (
	pod                   string = "Pod"
	replicaSet            string = "ReplicaSet"
	replicationController string = "ReplicationController"
	deployment            string = "Deployment"
	statefulset           string = "StatefulSet"
	daemonset             string = "DaemonSet"
	job                   string = "Job"
	cronJob               string = "CronTab"
	service               string = "Service"
	configmap             string = "ConfigMap"
	networkpolicy         string = "NetworkPolicy"
	namespace             string = "Namespace"
	list                  string = "List"
)

type deployObject struct {
	GroupKind     string
	RuntimeObject []byte
}

type parsedK8sObjects struct {
	ManifestFilepath string
	ManifestFilehash string
	DeployObjects    []deployObject
}

func FilesToObjectsList(path string) ([]K8sObject, error) {
	res := []K8sObject{}
	parsedObjects := getK8sDeploymentResources(&path)
	for _, obj := range parsedObjects {
		for _, o := range obj.DeployObjects {
			kind := o.GroupKind
			fmt.Printf("%v", kind)
			if kind == "Pod" || kind == "NetworkPolicy" || kind == "Namespace" || kind == "List" {
				res1, err := ScanK8sDeployObject(kind, o.RuntimeObject)
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

//getK8sDeploymentResources :
func getK8sDeploymentResources(repoDir *string) []parsedK8sObjects {
	manifestFiles := searchDeploymentManifests(repoDir)
	if len(manifestFiles) == 0 {
		//zap.S().Info("no deployment manifest found")
		return nil
	}
	parsedObjs := []parsedK8sObjects{}
	for _, mfp := range manifestFiles {
		if filebuf, err := ioutil.ReadFile(mfp); err == nil {
			p := parsedK8sObjects{}
			p.ManifestFilepath = mfp
			if pathSplit := strings.Split(mfp, *repoDir); len(pathSplit) > 1 {
				p.ManifestFilepath = pathSplit[1]
			}
			p.ManifestFilehash = fmt.Sprintf("%x", md5.Sum(filebuf))
			p.DeployObjects = parseK8sYaml(filebuf)
			parsedObjs = append(parsedObjs, p)
		}
	}
	return parsedObjs
}

//searchDeploymentManifests :
func searchDeploymentManifests(repoDir *string) []string {
	yamls := []string{}
	filepath.Walk(*repoDir, func(path string, f os.FileInfo, _ error) error {
		if f != nil {
			if !f.IsDir() {
				r, err := regexp.MatchString(".yaml", f.Name())
				if err == nil && r {
					yamls = append(yamls, path)
				}
			}
		}
		return nil
	})
	filepath.Walk(*repoDir, func(path string, f os.FileInfo, _ error) error {
		if f != nil {
			if !f.IsDir() {
				r, err := regexp.MatchString(".yml", f.Name())
				if err == nil && r {
					yamls = append(yamls, path)
				}
			}
		}
		return nil
	})
	return yamls
}

func ParseListNew(objDataBuf []byte) []K8sObject {
	r := bytes.NewReader(objDataBuf)
	res := []K8sObject{}
	if r == nil {
		return res
	}
	podsList := v1.PodList{}
	nsList := v1.NamespaceList{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&podsList)
	if err == nil && len(podsList.Items) > 0 && podsList.Items[0].TypeMeta.Kind == "Pod" {
		for i := range podsList.Items {
			res = append(res, K8sObject{pod: &podsList.Items[i], kind: "Pod"})
		}
		return res
	}
	r = bytes.NewReader(objDataBuf)
	err = yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&nsList)
	if err == nil && len(nsList.Items) > 0 && nsList.Items[0].TypeMeta.Kind == "Namespace" {
		for i := range nsList.Items {
			res = append(res, K8sObject{namespace: &nsList.Items[i], kind: "Namespace"})
		}
		return res
	}
	return res

}

func ParseList(r io.Reader) *v1.PodList {
	if r == nil {
		return nil
	}
	rc := v1.PodList{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

// ParsePod parses replicationController
func ParsePod(r io.Reader) *v1.Pod {
	if r == nil {
		return nil
	}
	rc := v1.Pod{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func ParseNamespace(r io.Reader) *v1.Namespace {
	if r == nil {
		return nil
	}
	rc := v1.Namespace{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

func ParseNetworkPolicy(r io.Reader) *netv1.NetworkPolicy {
	if r == nil {
		return nil
	}
	rc := netv1.NetworkPolicy{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

// ParseDeployment parses deployment
func ParseDeployment(r io.Reader) *appsv1.Deployment {
	if r == nil {
		return nil
	}
	rc := appsv1.Deployment{}
	err := yaml.NewYAMLOrJSONDecoder(r, 100).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

// ParseReplicaSet parses replicaset
func ParseReplicaSet(r io.Reader) *appsv1.ReplicaSet {
	if r == nil {
		return nil
	}
	rc := appsv1.ReplicaSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

// ParseReplicationController parses replicationController
func ParseReplicationController(r io.Reader) *v1.ReplicationController {
	if r == nil {
		return nil
	}
	rc := v1.ReplicationController{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}

	return &rc
}

// ParseDaemonSet parses replicationController
func ParseDaemonSet(r io.Reader) *appsv1.DaemonSet {
	if r == nil {
		return nil
	}
	rc := appsv1.DaemonSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}

	return &rc
}

// ParseStatefulSet parses replicationController
func ParseStatefulSet(r io.Reader) *appsv1.StatefulSet {
	if r == nil {
		return nil
	}
	rc := appsv1.StatefulSet{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}

	return &rc
}

// ParseJob parses replicationController
func ParseJob(r io.Reader) *batchv1.Job {
	if r == nil {
		return nil
	}
	rc := batchv1.Job{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}

	return &rc
}

// ParseService parses replicationController
func ParseService(r io.Reader) *v1.Service {
	if r == nil {
		return nil
	}
	rc := v1.Service{}
	err := yaml.NewYAMLOrJSONDecoder(r, 200).Decode(&rc)
	if err != nil {
		return nil
	}
	return &rc
}

//ScanK8sDeployObject :
func ScanK8sDeployObject(kind string, objDataBuf []byte) ([]K8sObject, error) {

	res := []K8sObject{}

	switch kind {
	case "Pod":
		obj := ParsePod(bytes.NewReader(objDataBuf))
		//res.pod = obj
		//res.kind = kind
		res = append(res, K8sObject{pod: obj, kind: kind})
	case "ReplicaSet":
		obj := ParseReplicaSet(bytes.NewReader(objDataBuf))
		//res.replicaset = obj
		//res.kind = kind
		res = append(res, K8sObject{replicaset: obj, kind: kind})
	case "NetworkPolicy":
		obj := ParseNetworkPolicy(bytes.NewReader(objDataBuf))
		//res.networkpolicy = obj
		//res.kind = kind
		res = append(res, K8sObject{networkpolicy: obj, kind: kind})
	case "Namespace":
		obj := ParseNamespace(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{namespace: obj, kind: kind})
		//res.namespace = obj
		//res.kind = kind
	case "List":
		obj := ParseListNew(objDataBuf)
		res = obj
		//fmt.Printf("%v", obj)
		//res.kind = kind

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
			//zap.S().Warn(err) // document decode failed
		}
		if len(doc) > 0 {
			out, _ := yamlv3.Marshal(doc)
			//if err != nil {
			//	zap.S().Warn(err) // document marshal failed
			//}
			documents = append(documents, string(out))
		}
	}
	return documents
}

func parseK8sYaml(fileR []byte) []deployObject {
	dObjs := []deployObject{}
	acceptedK8sTypes := regexp.MustCompile(fmt.Sprintf("(%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s)",
		pod, replicaSet, replicationController, deployment, daemonset, statefulset, job, cronJob, service, configmap, networkpolicy, namespace, list))
	//fileAsString := string(fileR[:])
	//sepYamlfiles := regexp.MustCompile("---\\s").Split(fileAsString, -1)
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
			//zap.S().Infof("Skipping object with type: %s", groupVersionKind.Kind)
			fmt.Printf("Skipping object with type: %v", groupVersionKind.Kind)
		} else {
			d := deployObject{}
			d.GroupKind = groupVersionKind.Kind
			d.RuntimeObject = []byte(f)
			dObjs = append(dObjs, d)
		}
	}
	return dObjs
}

// Exists Check whether a file with a given path exists
func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
