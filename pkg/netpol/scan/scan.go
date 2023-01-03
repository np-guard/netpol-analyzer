package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

// Walk function is a function for recursively scanning a directory, in the spirit of Go's native filepath.WalkDir()
// See https://pkg.go.dev/path/filepath#WalkDir for full description on how such file should work
type WalkFunction func(root string, fn fs.WalkDirFunc) error

// K8sObject holds a an object kind and a pointer of the relevant object
type K8sObject struct {
	Kind string
	// namespace object
	Namespace *v1.Namespace

	// netpol object
	Networkpolicy *netv1.NetworkPolicy

	// pod object
	Pod *v1.Pod

	// workload object
	Replicaset            *appsv1.ReplicaSet
	Deployment            *appsv1.Deployment
	Statefulset           *appsv1.StatefulSet
	ReplicationController *v1.ReplicationController
	Job                   *batchv1.Job
	CronJob               *batchv1.CronJob
	Daemonset             *appsv1.DaemonSet
}

// YAMLDocumentsToObjectsList returns a list of K8sObject parsed from input YAML documents
func YAMLDocumentsToObjectsList(documents []string) ([]K8sObject, error) {
	res := make([]K8sObject, 0)
	for _, manifest := range documents {
		if isAcceptedType, kind := getKind(manifest); isAcceptedType {
			if k8sObjects, err := mainfestToK8sObjects(manifest, kind); err == nil {
				res = append(res, k8sObjects...)
			} else {
				return res, err
			}
		}
	}
	return res, nil
}

// GetYAMLDocumentsFromPath returns a list of YAML documents from input dir path
func GetYAMLDocumentsFromPath(repoDir string, walkFn WalkFunction) []string {
	res := make([]string, 0)
	manifestFiles := searchDeploymentManifests(repoDir, walkFn)
	for _, mfp := range manifestFiles {
		filebuf, err := os.ReadFile(mfp)
		if err != nil {
			continue
		}
		res = append(res, splitByYamlDocuments(filebuf)...)
	}
	return res
}

// FilesToObjectsList returns a list of K8sObject parsed from yaml files in the input dir path
func FilesToObjectsList(path string, walkFn WalkFunction) ([]K8sObject, error) {
	manifests := GetYAMLDocumentsFromPath(path, walkFn)
	return YAMLDocumentsToObjectsList(manifests)
}

// FilesToObjectsListFiltered returns only K8sObjects from dir path if they match input pods namespaces (for non pod resources)
// and full input pods names for pod resources
func FilesToObjectsListFiltered(path string, walkFn WalkFunction, podNames []types.NamespacedName) ([]K8sObject, error) {
	allObjects, err := FilesToObjectsList(path, walkFn)
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

var (
	acceptedK8sTypesRegex = fmt.Sprintf("(^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$)",
		Pod, ReplicaSet, ReplicationController, Deployment, Daemonset, Statefulset, Job, CronJob,
		Networkpolicy, Namespace, List, NamespaceList, PodList)
	acceptedK8sTypes = regexp.MustCompile(acceptedK8sTypesRegex)
	yamlSuffix       = regexp.MustCompile(".ya?ml$")
)

// relevant K8s resource kinds as string values
const (
	Networkpolicy         string = "NetworkPolicy"
	Namespace             string = "Namespace"
	Pod                   string = "Pod"
	ReplicaSet            string = "ReplicaSet"
	ReplicationController string = "ReplicationController"
	Deployment            string = "Deployment"
	Statefulset           string = "StatefulSet"
	Daemonset             string = "DaemonSet"
	Job                   string = "Job"
	CronJob               string = "CronJob"
	List                  string = "List"
	NamespaceList         string = "NamespaceList"
	PodList               string = "PodList"
)

// the k8s kinds that scan pkg supports, without List kinds
var singleResourceK8sKinds = map[string]struct{}{
	Pod:                   {},
	Networkpolicy:         {},
	Namespace:             {},
	ReplicaSet:            {},
	Deployment:            {},
	Statefulset:           {},
	Daemonset:             {},
	Job:                   {},
	CronJob:               {},
	ReplicationController: {},
}

// given a YAML file content, split to a list of YAML documents
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

// return if yamlDoc is of accepted kind, and the kind string
func getKind(yamlDoc string) (bool, string) {
	if yamlDoc == "\n" || yamlDoc == "" {
		// ignore empty cases
		return false, ""
	}
	decode := scheme.Codecs.UniversalDeserializer().Decode
	_, groupVersionKind, err := decode([]byte(yamlDoc), nil, nil)
	if err != nil {
		return false, ""
	}
	if !acceptedK8sTypes.MatchString(groupVersionKind.Kind) {
		fmt.Printf("Skipping object with type: %s", groupVersionKind.Kind)
		return false, ""
	}
	return true, groupVersionKind.Kind
}

// given a YAML doc and its resource kind, convert to a slice of K8sObject
func mainfestToK8sObjects(yamlDoc, kind string) ([]K8sObject, error) {
	objDataBuf := []byte(yamlDoc)
	res := make([]K8sObject, 0, 1)
	switch kind {
	case Pod:
		obj := parsePod(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Pod: obj, Kind: kind})
	case ReplicaSet:
		obj := parseReplicaSet(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Replicaset: obj, Kind: kind})
	case Deployment:
		obj := parseDeployment(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Deployment: obj, Kind: kind})
	case Statefulset:
		obj := parseStatefulSet(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Statefulset: obj, Kind: kind})
	case ReplicationController:
		obj := parseReplicationController(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{ReplicationController: obj, Kind: kind})
	case Daemonset:
		obj := parseDaemonSet(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Daemonset: obj, Kind: kind})
	case Job:
		obj := parseJob(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Job: obj, Kind: kind})
	case CronJob:
		obj := parseCronJob(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{CronJob: obj, Kind: kind})
	case Networkpolicy:
		obj := parseNetworkPolicy(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Networkpolicy: obj, Kind: kind})
	case Namespace:
		obj := parseNamespace(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Namespace: obj, Kind: kind})
	case List:
		res = parseList(objDataBuf)
	case PodList:
		res = parsePodList(objDataBuf)
	case NamespaceList:
		res = parseNamespaceList(objDataBuf)
	// TODO: support other specific list types, other than PodList and NamespaceList
	default:
		return res, fmt.Errorf("unsupported kind: %s", kind)
	}
	return res, nil
}

const yamlParseBufferSize = 200

// return a list of paths for yaml files in the input dir path
func searchDeploymentManifests(repoDir string, walkFn WalkFunction) []string {
	yamls := make([]string, 0)
	err := walkFn(repoDir, func(path string, f os.DirEntry, err error) error {
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

// given YAML of kind "List" , parse and convert to slice of K8sObject
func parseList(objDataBuf []byte) []K8sObject {
	for kind := range singleResourceK8sKinds {
		if isKind, resList := parseListOfKind(objDataBuf, kind); isKind {
			return resList
		}
	}
	return nil
}

// given YAML of kind "NamespaceList" , parse and convert to slice of K8sObject
func parseNamespaceList(objDataBuf []byte) []K8sObject {
	if isKind, resList := parseListOfKind(objDataBuf, Namespace); isKind {
		return resList
	}
	return nil
}

// given YAML of kind "PodList" , parse and convert to slice of K8sObject
func parsePodList(objDataBuf []byte) []K8sObject {
	if isKind, resList := parseListOfKind(objDataBuf, Pod); isKind {
		return resList
	}
	return nil
}

// given a parsed k8s object's namespace and kind, validate its kind, and assign kind or namespace if missing
// return true if the actual kind matches the expected kind
func validateNamespaceAndKind(namespace, kind *string, expectedKind string) (bool, error) {
	if namespace != nil && *namespace == metav1.NamespaceNone {
		*namespace = metav1.NamespaceDefault
	}
	if kind != nil && *kind != "" && *kind != expectedKind {
		return false, errors.New("unexpected kind")
	}
	if kind != nil && *kind == "" {
		*kind = expectedKind
	}
	return true, nil
}

func convertPodListTOK8sObjects(pl *v1.PodList) ([]K8sObject, error) {
	res := make([]K8sObject, len(pl.Items))
	for i := range pl.Items {
		if isValidKind, err := validateNamespaceAndKind(&pl.Items[i].Namespace, &pl.Items[i].Kind, Pod); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Pod: &pl.Items[i], Kind: Pod}
	}
	return res, nil
}

func convertNamespaceListTOK8sObjects(nsl *v1.NamespaceList) ([]K8sObject, error) {
	res := make([]K8sObject, len(nsl.Items))
	for i := range nsl.Items {
		if isValidKind, err := validateNamespaceAndKind(nil, &nsl.Items[i].Kind, Namespace); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Namespace: &nsl.Items[i], Kind: Namespace}
	}
	return res, nil
}

func convertNetpolListTOK8sObjects(nl *netv1.NetworkPolicyList) ([]K8sObject, error) {
	res := make([]K8sObject, len(nl.Items))
	for i := range nl.Items {
		if isValidKind, err := validateNamespaceAndKind(&nl.Items[i].Namespace, &nl.Items[i].Kind, Networkpolicy); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Networkpolicy: &nl.Items[i], Kind: Networkpolicy}
	}
	return res, nil
}

func convertReplicaSetListTOK8sObjects(rsl *appsv1.ReplicaSetList) ([]K8sObject, error) {
	res := make([]K8sObject, len(rsl.Items))
	for i := range rsl.Items {
		if isValidKind, err := validateNamespaceAndKind(&rsl.Items[i].Namespace, &rsl.Items[i].Kind, ReplicaSet); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Replicaset: &rsl.Items[i], Kind: ReplicaSet}
	}
	return res, nil
}

func convertDeploymentListTOK8sObjects(dl *appsv1.DeploymentList) ([]K8sObject, error) {
	res := make([]K8sObject, len(dl.Items))
	for i := range dl.Items {
		if isValidKind, err := validateNamespaceAndKind(&dl.Items[i].Namespace, &dl.Items[i].Kind, Deployment); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Deployment: &dl.Items[i], Kind: Deployment}
	}
	return res, nil
}

func convertStatefulSetListTOK8sObjects(sl *appsv1.StatefulSetList) ([]K8sObject, error) {
	res := make([]K8sObject, len(sl.Items))
	for i := range sl.Items {
		if isValidKind, err := validateNamespaceAndKind(&sl.Items[i].Namespace, &sl.Items[i].Kind, Statefulset); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Statefulset: &sl.Items[i], Kind: Statefulset}
	}
	return res, nil
}

func convertDaemonSetListTOK8sObjects(sl *appsv1.DaemonSetList) ([]K8sObject, error) {
	res := make([]K8sObject, len(sl.Items))
	for i := range sl.Items {
		if isValidKind, err := validateNamespaceAndKind(&sl.Items[i].Namespace, &sl.Items[i].Kind, Daemonset); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Daemonset: &sl.Items[i], Kind: Daemonset}
	}
	return res, nil
}

func convertReplicationControllerListTOK8sObjects(sl *v1.ReplicationControllerList) ([]K8sObject, error) {
	res := make([]K8sObject, len(sl.Items))
	for i := range sl.Items {
		if isValidKind, err := validateNamespaceAndKind(&sl.Items[i].Namespace, &sl.Items[i].Kind, ReplicationController); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{ReplicationController: &sl.Items[i], Kind: ReplicationController}
	}
	return res, nil
}

func convertJobListTOK8sObjects(sl *batchv1.JobList) ([]K8sObject, error) {
	res := make([]K8sObject, len(sl.Items))
	for i := range sl.Items {
		if isValidKind, err := validateNamespaceAndKind(&sl.Items[i].Namespace, &sl.Items[i].Kind, Job); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Job: &sl.Items[i], Kind: Job}
	}
	return res, nil
}

func convertCronJobListTOK8sObjects(sl *batchv1.CronJobList) ([]K8sObject, error) {
	res := make([]K8sObject, len(sl.Items))
	for i := range sl.Items {
		if isValidKind, err := validateNamespaceAndKind(&sl.Items[i].Namespace, &sl.Items[i].Kind, CronJob); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{CronJob: &sl.Items[i], Kind: CronJob}
	}
	return res, nil
}

//gocyclo:ignore
func getListObjects(parsedList interface{}, kind string) ([]K8sObject, error) {
	switch kind {
	case Pod:
		if podList, ok := parsedList.(*v1.PodList); ok {
			return convertPodListTOK8sObjects(podList)
		}
	case Namespace:
		if nsList, ok := parsedList.(*v1.NamespaceList); ok {
			return convertNamespaceListTOK8sObjects(nsList)
		}
	case Networkpolicy:
		if netpolList, ok := parsedList.(*netv1.NetworkPolicyList); ok {
			return convertNetpolListTOK8sObjects(netpolList)
		}
	case ReplicaSet:
		if rsList, ok := parsedList.(*appsv1.ReplicaSetList); ok {
			return convertReplicaSetListTOK8sObjects(rsList)
		}
	case Deployment:
		if dlList, ok := parsedList.(*appsv1.DeploymentList); ok {
			return convertDeploymentListTOK8sObjects(dlList)
		}
	case Statefulset:
		if slList, ok := parsedList.(*appsv1.StatefulSetList); ok {
			return convertStatefulSetListTOK8sObjects(slList)
		}
	case Daemonset:
		if dslList, ok := parsedList.(*appsv1.DaemonSetList); ok {
			return convertDaemonSetListTOK8sObjects(dslList)
		}
	case ReplicationController:
		if dslList, ok := parsedList.(*v1.ReplicationControllerList); ok {
			return convertReplicationControllerListTOK8sObjects(dslList)
		}
	case Job:
		if dslList, ok := parsedList.(*batchv1.JobList); ok {
			return convertJobListTOK8sObjects(dslList)
		}
	case CronJob:
		if dslList, ok := parsedList.(*batchv1.CronJobList); ok {
			return convertCronJobListTOK8sObjects(dslList)
		}
	}
	return nil, fmt.Errorf("invalid kind: %s", kind)
}

func parseListOfKind(objDataBuf []byte, kind string) (bool, []K8sObject) {
	r := bytes.NewReader(objDataBuf)
	var err error
	var resList interface{}

	switch kind {
	case Pod:
		resList = &v1.PodList{}
	case Namespace:
		resList = &v1.NamespaceList{}
	case Networkpolicy:
		resList = &netv1.NetworkPolicyList{}
	case ReplicaSet:
		resList = &appsv1.ReplicaSetList{}
	case Deployment:
		resList = &appsv1.DeploymentList{}
	case Statefulset:
		resList = &appsv1.StatefulSetList{}
	case ReplicationController:
		resList = &v1.ReplicationControllerList{}
	case Daemonset:
		resList = &appsv1.DaemonSetList{}
	case Job:
		resList = &batchv1.JobList{}
	case CronJob:
		resList = &batchv1.CronJobList{}
	}
	err = yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(resList)
	if err != nil {
		return false, nil
	}
	listObjects, err := getListObjects(resList, kind)
	if err != nil {
		return false, nil
	}

	return true, listObjects
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Pod); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Networkpolicy); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, ReplicaSet); !isValid || err != nil {
		return nil
	}
	return &rc
}

func parseReplicationController(r io.Reader) *v1.ReplicationController {
	if r == nil {
		return nil
	}
	rc := v1.ReplicationController{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, ReplicationController); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Daemonset); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Statefulset); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Job); !isValid || err != nil {
		return nil
	}
	return &rc
}

func parseCronJob(r io.Reader) *batchv1.CronJob {
	if r == nil {
		return nil
	}
	rc := batchv1.CronJob{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, CronJob); !isValid || err != nil {
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
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Deployment); !isValid || err != nil {
		return nil
	}
	return &rc
}
