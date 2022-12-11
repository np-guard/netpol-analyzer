package scan

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// FilesToObjectsListFiltered returns only K8sObjects from dir path if they match input pods namespaces (for non pod resources)
// and full input pods names for pod resources
func FilesToObjectsListFiltered(path string, podNames []types.NamespacedName) ([]K8sObject, error) {
	allObjects, err := FilesToObjectsList(path)
	if err != nil {
		return nil, err
	}
	podNamesMap := make(map[string]bool, 0)
	nsMap := make(map[string]bool, 0)
	for i := range podNames {
		podNamesMap[podNames[i].String()] = true
		nsMap[podNames[i].Namespace] = true
	}
	res := make([]K8sObject, 0)
	for _, obj := range allObjects {
		if obj.Kind == Namespace {
			if _, ok := nsMap[obj.Namespace.Name]; ok {
				res = append(res, obj)
			}
		} else if obj.Kind == Networkpolicy {
			if _, ok := nsMap[obj.Networkpolicy.Namespace]; ok {
				res = append(res, obj)
			}
		} else if obj.Kind == Pod {
			if _, ok := podNamesMap[types.NamespacedName{Name: obj.Pod.Name, Namespace: obj.Pod.Namespace}.String()]; ok {
				res = append(res, obj)
			}
		}
	}
	return res, nil
}

// FilesToObjectsList returns a list of K8sObject parsed from yaml files in the input dir path
func FilesToObjectsList(path string) ([]K8sObject, error) {
	manifests := GetYAMLDocumentsFromPath(path)
	return YAMLDocumentsToObjectsList(manifests)
}

// YAMLDocumentsToObjectsList returns a list of K8sObject parsed from input YAML documents
func YAMLDocumentsToObjectsList(documents []string) ([]K8sObject, error) {
	res := make([]K8sObject, 0)
	for _, manifest := range documents {
		parsedObject := parseK8sYaml(manifest)
		if k8sObjects, err := deployObjectsToK8sObjects(parsedObject); err == nil {
			res = append(res, k8sObjects...)
		} else {
			return res, err
		}
	}
	return res, nil
}

func deployObjectsToK8sObjects(deployobjects []deployObject) ([]K8sObject, error) {
	res := make([]K8sObject, 0)
	for _, o := range deployobjects {
		kind := o.groupKind
		if kind == Pod || kind == Networkpolicy || kind == Namespace || kind == List || kind == PodList || kind == NamespaceList {
			k8sObjects, err := scanK8sDeployObject(kind, o.runtimeObject)
			if err == nil {
				res = append(res, k8sObjects...)
			} else {
				return res, err
			}
		}
	}
	return res, nil
}

const (
	Pod                   string = "Pod"
	ReplicaSet            string = "ReplicaSet"
	ReplicationController string = "ReplicationController"
	Deployment            string = "Deployment"
	Statefulset           string = "StatefulSet"
	Daemonset             string = "DaemonSet"
	Job                   string = "Job"
	CronJob               string = "CronJob"
	Service               string = "Service"
	Configmap             string = "ConfigMap"
	Networkpolicy         string = "NetworkPolicy"
	Namespace             string = "Namespace"
	List                  string = "List"
	NamespaceList         string = "NamespaceList"
	PodList               string = "PodList"
)

var (
	acceptedK8sTypesRegex = fmt.Sprintf("(%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s)",
		Pod, ReplicaSet, ReplicationController, Deployment, Daemonset, Statefulset, Job, CronJob,
		Service, Configmap, Networkpolicy, Namespace, List, NamespaceList, PodList)
	acceptedK8sTypes = regexp.MustCompile(acceptedK8sTypesRegex)
	yamlSuffix       = regexp.MustCompile(".ya?ml$")
)

const yamlParseBufferSize = 200

type deployObject struct {
	groupKind     string
	runtimeObject []byte
}

func GetYAMLDocumentsFromPath(repoDir string) []string {
	res := make([]string, 0)
	manifestFiles := searchDeploymentManifests(repoDir)
	for _, mfp := range manifestFiles {
		filebuf, err := os.ReadFile(mfp)
		if err != nil {
			continue
		}
		res = append(res, splitByYamlDocuments(filebuf)...)
	}
	return res
}

// return a list of paths for yaml files in the input dir path
func searchDeploymentManifests(repoDir string) []string {
	yamls := make([]string, 0)
	err := filepath.WalkDir(repoDir, func(path string, f os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if f != nil && !f.IsDir() && yamlSuffix.MatchString(f.Name()) {
			yamls = append(yamls, path)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error: Error in searching for manifests: %v", err)
	}
	return yamls
}

func parseNamespaceList(objDataBuf []byte) []K8sObject {
	r := bytes.NewReader(objDataBuf)
	res := make([]K8sObject, 0)
	if r == nil {
		return res
	}
	nsList := v1.NamespaceList{}
	if err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&nsList); err == nil {
		for i := range nsList.Items {
			nsList.Items[i].Kind = Namespace
			res = append(res, K8sObject{Namespace: &nsList.Items[i], Kind: Namespace})
		}
	}
	return res
}

func parsePodList(objDataBuf []byte) []K8sObject {
	r := bytes.NewReader(objDataBuf)
	res := make([]K8sObject, 0)
	if r == nil {
		return res
	}
	podsList := v1.PodList{}
	if err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&podsList); err == nil {
		for i := range podsList.Items {
			if podsList.Items[i].Namespace == metav1.NamespaceNone {
				podsList.Items[i].Namespace = metav1.NamespaceDefault
			}
			podsList.Items[i].Kind = Pod
			res = append(res, K8sObject{Pod: &podsList.Items[i], Kind: Pod})
		}
	}
	return res
}

func parseList(objDataBuf []byte) []K8sObject {
	r := bytes.NewReader(objDataBuf)
	res := make([]K8sObject, 0)
	if r == nil {
		return res
	}
	podsList := v1.PodList{}
	nsList := v1.NamespaceList{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&podsList)
	// currently supporting list of pods or namespaces
	if err == nil && len(podsList.Items) > 0 && podsList.Items[0].TypeMeta.Kind == Pod {
		for i := range podsList.Items {
			if podsList.Items[i].Namespace == metav1.NamespaceNone {
				podsList.Items[i].Namespace = metav1.NamespaceDefault
			}
			res = append(res, K8sObject{Pod: &podsList.Items[i], Kind: Pod})
		}
		return res
	}
	r = bytes.NewReader(objDataBuf)
	err = yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&nsList)
	if err == nil && len(nsList.Items) > 0 && nsList.Items[0].TypeMeta.Kind == Namespace {
		for i := range nsList.Items {
			res = append(res, K8sObject{Namespace: &nsList.Items[i], Kind: Namespace})
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
	if rc.Namespace == metav1.NamespaceNone {
		rc.Namespace = metav1.NamespaceDefault
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
	if rc.Namespace == metav1.NamespaceNone {
		rc.Namespace = metav1.NamespaceDefault
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
	if rc.Namespace == metav1.NamespaceNone {
		rc.Namespace = metav1.NamespaceDefault
	}
	return &rc
}

func scanK8sDeployObject(kind string, objDataBuf []byte) ([]K8sObject, error) {
	res := make([]K8sObject, 0)

	switch kind {
	case Pod:
		obj := parsePod(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Pod: obj, Kind: kind})
	case ReplicaSet:
		obj := parseReplicaSet(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Replicaset: obj, Kind: kind})
	case Networkpolicy:
		obj := parseNetworkPolicy(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Networkpolicy: obj, Kind: kind})
	case Namespace:
		obj := parseNamespace(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Namespace: obj, Kind: kind})
	case List:
		obj := parseList(objDataBuf)
		res = obj
	case PodList:
		obj := parsePodList(objDataBuf)
		res = obj
	case NamespaceList:
		obj := parseNamespaceList(objDataBuf)
		res = obj
	default:
		return res, fmt.Errorf("unsupported object type: `%s`", kind)
	}
	return res, nil
}

func splitByYamlDocuments(data []byte) []string {
	decoder := yamlv3.NewDecoder(bytes.NewBuffer(data))
	documents := make([]string, 0)
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

func parseK8sYaml(YAMLDoc string) []deployObject {
	dObjs := make([]deployObject, 0)

	if YAMLDoc == "\n" || YAMLDoc == "" {
		// ignore empty cases
		return dObjs
	}
	decode := scheme.Codecs.UniversalDeserializer().Decode
	_, groupVersionKind, err := decode([]byte(YAMLDoc), nil, nil)
	if err != nil {
		return dObjs
	}

	if !acceptedK8sTypes.MatchString(groupVersionKind.Kind) {
		fmt.Printf("Skipping object with type: %s", groupVersionKind.Kind)
		return dObjs
	} else {
		d := deployObject{}
		d.groupKind = groupVersionKind.Kind
		d.runtimeObject = []byte(YAMLDoc)
		dObjs = append(dObjs, d)
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
