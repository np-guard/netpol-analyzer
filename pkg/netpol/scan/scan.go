package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"encoding/json"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/cli-runtime/pkg/resource"

	ocapiv1 "github.com/openshift/api"
	ocroutev1 "github.com/openshift/api/route/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
)

// IPv4LoopbackAddr is used as fake IP in the absence of Pod.Status.HostIP or Pod.Status.PodIPs
const IPv4LoopbackAddr = "127.0.0.1"

type ResourcesScanner struct {
	logger               logger.Logger
	stopOnError          bool
	walkFn               WalkFunction
	resourceDecoder      runtime.Decoder
	includeJSONManifests bool
}

func NewResourcesScanner(
	l logger.Logger,
	stopOnError bool,
	walkFn WalkFunction,
	includeJSONManifests bool) *ResourcesScanner {
	res := ResourcesScanner{logger: l, stopOnError: stopOnError, walkFn: walkFn, includeJSONManifests: includeJSONManifests}

	scheme := runtime.NewScheme()
	Codecs := serializer.NewCodecFactory(scheme)
	_ = ocapiv1.InstallKube(scheme) // returned error is ignored - seems to be always nil
	_ = ocapiv1.Install(scheme)     // returned error is ignored - seems to be always nil
	res.resourceDecoder = Codecs.UniversalDeserializer()

	return &res
}

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

	// service object
	Service *v1.Service

	// Ingress objects
	Route   *ocroutev1.Route
	Ingress *netv1.Ingress

	// workload object
	Replicaset            *appsv1.ReplicaSet
	Deployment            *appsv1.Deployment
	Statefulset           *appsv1.StatefulSet
	ReplicationController *v1.ReplicationController
	Job                   *batchv1.Job
	CronJob               *batchv1.CronJob
	Daemonset             *appsv1.DaemonSet
}

func (k *K8sObject) getEmptyInitializedFieldObjByKind(kind string) interface{} {
	switch kind {
	case Deployment:
		k.Deployment = &appsv1.Deployment{}
		return k.Deployment
	case Daemonset:
		k.Daemonset = &appsv1.DaemonSet{}
		return k.Daemonset
	case ReplicaSet:
		k.Replicaset = &appsv1.ReplicaSet{}
		return k.Replicaset
	case Statefulset:
		k.Statefulset = &appsv1.StatefulSet{}
		return k.Statefulset
	case ReplicationController:
		k.ReplicationController = &v1.ReplicationController{}
		return k.ReplicationController
	case Job:
		k.Job = &batchv1.Job{}
		return k.Job
	case CronJob:
		k.CronJob = &batchv1.CronJob{}
		return k.CronJob
	case Route:
		k.Route = &ocroutev1.Route{}
		return k.Route
	case Ingress:
		k.Ingress = &netv1.Ingress{}
		return k.Ingress
	case Service:
		k.Service = &v1.Service{}
		return k.Service
	case Pod:
		k.Pod = &v1.Pod{}
		return k.Pod
	case Networkpolicy:
		k.Networkpolicy = &netv1.NetworkPolicy{}
		return k.Networkpolicy
	case Namespace:
		k.Namespace = &v1.Namespace{}
		return k.Namespace
	}
	return nil
}

//gocyclo:ignore
func (k *K8sObject) initDefaultNamespace() {
	switch k.Kind {
	case Deployment:
		if k.Deployment.Namespace == "" {
			k.Deployment.Namespace = metav1.NamespaceDefault
		}
	case Daemonset:
		if k.Daemonset.Namespace == "" {
			k.Daemonset.Namespace = metav1.NamespaceDefault
		}
	case ReplicaSet:
		if k.Replicaset.Namespace == "" {
			k.Replicaset.Namespace = metav1.NamespaceDefault
		}
	case Statefulset:
		if k.Statefulset.Namespace == "" {
			k.Statefulset.Namespace = metav1.NamespaceDefault
		}
	case ReplicationController:
		if k.ReplicationController.Namespace == "" {
			k.ReplicationController.Namespace = metav1.NamespaceDefault
		}
	case Job:
		if k.Job.Namespace == "" {
			k.Job.Namespace = metav1.NamespaceDefault
		}
	case CronJob:
		if k.CronJob.Namespace == "" {
			k.CronJob.Namespace = metav1.NamespaceDefault
		}
	case Route:
		if k.Route.Namespace == "" {
			k.Route.Namespace = metav1.NamespaceDefault
		}
	case Ingress:
		if k.Ingress.Namespace == "" {
			k.Ingress.Namespace = metav1.NamespaceDefault
		}
	case Service:
		if k.Service.Namespace == "" {
			k.Service.Namespace = metav1.NamespaceDefault
		}
	case Pod:
		if k.Pod.Namespace == "" {
			k.Pod.Namespace = metav1.NamespaceDefault
		}
		checkAndUpdatePodStatusIPsFields(k.Pod)
	case Networkpolicy:
		if k.Networkpolicy.Namespace == "" {
			k.Networkpolicy.Namespace = metav1.NamespaceDefault
		}
	}
}

// ResourceInfoListToK8sObjectsList returns a list of K8sObject and list of FileProcessingError objects from analyzing
// an input list of resource.Info objects. Irrelevant resources are skipped.
// Possible errs/warnings as FileProcessingError:
// malformedYamlDoc , noK8sWorkloadResourcesFound, noK8sNetworkPolicyResourcesFound
func ResourceInfoListToK8sObjectsList(infosList []*resource.Info, l logger.Logger) ([]K8sObject, []FileProcessingError) {
	res := make([]K8sObject, 0)
	fpErrList := []FileProcessingError{}
	var hasWorkloads, hasNetpols bool
	for _, info := range infosList {
		// fpErr can be  malformedYamlDoc
		k8sObj, fpErr, isWorkload, isNetpol := resourceInfoToK8sObject(info, l)
		if fpErr != nil {
			fpErrList = append(fpErrList, *fpErr)
			// no need to stop if stopOnErr was set, since malformedYamlDoc is a warning
		}
		if k8sObj != nil && k8sObj.Kind != "" {
			res = append(res, *k8sObj)
			if isNetpol {
				hasNetpols = true
			}
			if isWorkload {
				hasWorkloads = true
			}
		}
	}
	if !hasWorkloads {
		fpErrList = appendAndLogNewError(fpErrList, missingResources(true, false), l)
	}
	if !hasNetpols {
		fpErrList = appendAndLogNewError(fpErrList, missingResources(false, true), l)
	}

	return res, fpErrList
}

// resourceInfoToK8sObject converts an input resource.Info object to a K8sObject
func resourceInfoToK8sObject(info *resource.Info, l logger.Logger) (*K8sObject, *FileProcessingError, bool, bool) {
	resObject := K8sObject{}
	if unstructuredObj, ok := info.Object.(*unstructured.Unstructured); ok {
		resObject.Kind = unstructuredObj.GetKind()
		var err error
		objField := resObject.getEmptyInitializedFieldObjByKind(resObject.Kind)
		if objField == nil {
			l.Infof("in file: %s, skipping object with type: %s", info.Source, resObject.Kind)
			return nil, nil, false, false
		}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, objField)
		if err != nil {
			kind := unstructuredObj.GetKind()
			name := unstructuredObj.GetName()
			namespace := unstructuredObj.GetNamespace()
			// malformed k8s resource
			resourceStr := getResourceInfoStr(kind, name, namespace)
			errStr := "error for resource"
			if resourceStr != "" {
				errStr += " with " + resourceStr
			}
			fpErr := malformedYamlDoc(info.Source, 0, -1, fmt.Errorf("%s:  %s", errStr, err))
			logError(l, fpErr)
			return nil, fpErr, false, false
		}
		resObject.initDefaultNamespace()
	} else {
		// failed conversion to unstructured
		fpErr := malformedYamlDoc(info.Source, 0, -1, fmt.Errorf("failed conversion from resource.Info to unstructured.Unstructured"))
		logError(l, fpErr)
		return nil, fpErr, false, false
	}

	isNetpol := resObject.Kind == Networkpolicy
	isWorkload := workloadKinds[resObject.Kind]
	return &resObject, nil, isWorkload, isNetpol
}

// error for resource with kind: , name: ,namespace: ,
func getResourceInfoStr(kind, name, namespace string) string {
	res := ""
	sep := " , "
	if kind != "" {
		res += "kind: " + kind + sep
	}
	if name != "" {
		res += "name: " + name + sep
	}
	if namespace != "" {
		res += "namespace: " + namespace + sep
	}
	return res
}

// YAMLDocumentsToObjectsList returns a list of K8sObject parsed from input YAML documents
func (sc *ResourcesScanner) YAMLDocumentsToObjectsList(documents []YAMLDocumentIntf) ([]K8sObject, []FileProcessingError) {
	res := make([]K8sObject, 0)
	errs := make([]FileProcessingError, 0)
	for _, manifest := range documents {
		isAcceptedType, kind, processingErrs := sc.getKind(manifest)
		if isAcceptedType {
			if k8sObjects, err := manifestToK8sObjects(manifest, kind); err == nil {
				res = append(res, k8sObjects...)
			} else {
				errs = appendAndLogNewError(errs, failedScanningResource(kind, manifest.FilePath(), err), sc.logger)
			}
		}
		errs = append(errs, processingErrs...)
		if stopProcessing(sc.stopOnError, errs) {
			return res, errs
		}
	}
	if len(res) == 0 {
		errs = appendAndLogNewError(errs, noK8sResourcesFound(), sc.logger)
	} else {
		hasWorkloads, hasNetpols := hasWorkloadsOrNetworkPolicies(res)
		if !hasWorkloads {
			errs = appendAndLogNewError(errs, noK8sWorkloadResourcesFound(), sc.logger)
		}
		if !hasNetpols {
			errs = appendAndLogNewError(errs, noK8sNetworkPolicyResourcesFound(), sc.logger)
		}
	}
	return res, errs
}

func missingResources(isWorkload, isNetpol bool) *FileProcessingError {
	if isWorkload {
		return noK8sWorkloadResourcesFound()
	}
	if isNetpol {
		return noK8sNetworkPolicyResourcesFound()
	}
	return nil
}

// YAMLDocumentIntf is an interface for holding YAML document
type YAMLDocumentIntf interface {
	// Content is the string content of the YAML doc
	Content() string
	// FilePath is the file path containing the YAML doc
	FilePath() string
	// DocID is the document ID of the YAML doc within the file
	DocID() int
}

// yamlDocument implements the YAMLDocumentIntf interface
type yamlDocument struct {
	content  string
	filePath string
	docID    int
}

func (yd *yamlDocument) Content() string {
	return yd.content
}
func (yd *yamlDocument) FilePath() string {
	return yd.filePath
}
func (yd *yamlDocument) DocID() int {
	return yd.docID
}

// GetYAMLDocumentsFromPath returns a list of YAML documents from input dir path
func (sc *ResourcesScanner) GetYAMLDocumentsFromPath(repoDir string) ([]YAMLDocumentIntf, []FileProcessingError) {
	res := make([]YAMLDocumentIntf, 0)
	manifestFilesMap, fileScanErrors := sc.searchYamlFiles(repoDir)
	if stopProcessing(sc.stopOnError, fileScanErrors) {
		return nil, fileScanErrors
	}

	if len(manifestFilesMap) == 0 {
		fileScanErrors = appendAndLogNewError(fileScanErrors, noYamlsFound(), sc.logger)
		return nil, fileScanErrors
	}

	for mfp, isYAML := range manifestFilesMap {
		yamlDocs, errs := sc.splitByYamlDocuments(mfp, isYAML)
		res = append(res, yamlDocs...)
		fileScanErrors = append(fileScanErrors, errs...)
		if stopProcessing(sc.stopOnError, errs) {
			return nil, fileScanErrors
		}
	}
	return res, fileScanErrors
}

// FilesToObjectsList returns a list of K8sObject parsed from yaml files in the input dir path
func (sc *ResourcesScanner) FilesToObjectsList(path string) ([]K8sObject, []FileProcessingError) {
	manifests, fileScanErrors := sc.GetYAMLDocumentsFromPath(path)
	if stopProcessing(sc.stopOnError, fileScanErrors) {
		return nil, fileScanErrors
	}
	objects, errs := sc.YAMLDocumentsToObjectsList(manifests)
	fileScanErrors = append(fileScanErrors, errs...)
	return objects, fileScanErrors
}

// FilesToObjectsListFiltered returns only K8sObjects from dir path if they match input pods namespaces (for non pod resources)
// and full input pods names for pod resources
//
//gocyclo:ignore
func (sc *ResourcesScanner) FilesToObjectsListFiltered(path string, podNames []types.NamespacedName) ([]K8sObject, []FileProcessingError) {
	allObjects, errs := sc.FilesToObjectsList(path)
	if stopProcessing(sc.stopOnError, errs) {
		return nil, errs
	}
	podNamesMap := make(map[string]bool, 0)
	nsMap := make(map[string]bool, 0)
	for i := range podNames {
		podNamesMap[podNames[i].String()] = true
		nsMap[podNames[i].Namespace] = true
	}
	res := make([]K8sObject, 0)
	for _, obj := range allObjects {
		switch obj.Kind {
		case Namespace:
			if _, ok := nsMap[obj.Namespace.Name]; ok {
				res = append(res, obj)
			}
		case Networkpolicy:
			if _, ok := nsMap[obj.Networkpolicy.Namespace]; ok {
				res = append(res, obj)
			}
		case Pod:
			if _, ok := podNamesMap[types.NamespacedName{Name: obj.Pod.Name, Namespace: obj.Pod.Namespace}.String()]; ok {
				res = append(res, obj)
			}
		case Service:
			if _, ok := nsMap[obj.Service.Namespace]; ok {
				res = append(res, obj)
			}
		case Route:
			if _, ok := nsMap[obj.Route.Namespace]; ok {
				res = append(res, obj)
			}
		case Ingress:
			if _, ok := nsMap[obj.Ingress.Namespace]; ok {
				res = append(res, obj)
			}
		default:
			continue
		}
	}
	return res, nil
}

var (
	acceptedK8sTypesRegex = fmt.Sprintf("(^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$|^%s$)",
		Pod, ReplicaSet, ReplicationController, Deployment, Daemonset, Statefulset, Job, CronJob,
		Networkpolicy, Namespace, Service, Route, Ingress, List, NamespaceList, PodList, NetworkpolicyList)
	acceptedK8sTypes = regexp.MustCompile(acceptedK8sTypesRegex)
	yamlSuffix       = regexp.MustCompile(".ya?ml$")
	jsonSuffix       = regexp.MustCompile(".json$")
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
	NetworkpolicyList     string = "NetworkPolicyList"
	PodList               string = "PodList"
	Service               string = "Service"
	Route                 string = "Route"
	Ingress               string = "Ingress"
)

// the k8s kinds that scan pkg supports, without List kinds, mapped to a bool flag indicating if it is a workload type or not
var singleResourceK8sKinds = map[string]bool{
	Pod:                   true,
	Networkpolicy:         false,
	Namespace:             false,
	ReplicaSet:            true,
	Deployment:            true,
	Statefulset:           true,
	Daemonset:             true,
	Job:                   true,
	CronJob:               true,
	ReplicationController: true,
	Service:               false,
	Route:                 false,
	Ingress:               false,
}

var workloadKinds = map[string]bool{
	Pod:                   true,
	ReplicaSet:            true,
	Deployment:            true,
	Statefulset:           true,
	Daemonset:             true,
	Job:                   true,
	CronJob:               true,
	ReplicationController: true,
}

func convertJSONInputToYAML(srcBytes []byte) ([]byte, error) {
	var data interface{}
	if err := json.Unmarshal(srcBytes, &data); err != nil {
		return nil, err
	}

	out, err := yamlv3.Marshal(data)
	if err != nil {
		return nil, err
	}
	// TODO: temporary work around (see issue with test_with_named_ports/pod_list.json)
	outString := strings.ReplaceAll(string(out), "ports: {}", "ports: []")

	return []byte(outString), nil
}

// given a YAML file content, split to a list of YAML documents. if isYAML is false, the input file is JSON
// and should be converted to YAML, and then split to its documents
func (sc *ResourcesScanner) splitByYamlDocuments(mfp string, isYAML bool) ([]YAMLDocumentIntf, []FileProcessingError) {
	fileBuf, err := os.ReadFile(mfp)
	if err != nil {
		return []YAMLDocumentIntf{}, appendAndLogNewError(nil, FailedReadingFile(mfp, err), sc.logger)
	}

	if !isYAML && sc.includeJSONManifests {
		// convert JSON to YAML
		fileBuf, err = convertJSONInputToYAML(fileBuf)
		if err != nil {
			return []YAMLDocumentIntf{}, appendAndLogNewError(nil, FailedReadingFile(mfp, err), sc.logger)
		}
	}

	decoder := yamlv3.NewDecoder(bytes.NewBuffer(fileBuf))
	documents := make([]YAMLDocumentIntf, 0)
	documentID := 0
	for {
		var doc yamlv3.Node
		if err := decoder.Decode(&doc); err != nil {
			if err != io.EOF {
				return documents, appendAndLogNewError(nil, malformedYamlDoc(mfp, 0, documentID, err), sc.logger)
			}
			break
		}
		if len(doc.Content) > 0 && doc.Content[0].Kind == yamlv3.MappingNode {
			out, err := yamlv3.Marshal(doc.Content[0])
			if err != nil {
				return documents, appendAndLogNewError(nil, malformedYamlDoc(mfp, doc.Line, documentID, err), sc.logger)
			}
			documents = append(documents, &yamlDocument{content: string(out), docID: documentID, filePath: mfp})
		}
		documentID += 1
	}
	return documents, nil
}

// return if yamlDoc is of accepted kind, and the kind string
func (sc *ResourcesScanner) getKind(yamlDoc YAMLDocumentIntf) (acceptedKind bool, kind string, processingErrs []FileProcessingError) {
	fileProcessingErrors := make([]FileProcessingError, 0)
	_, groupVersionKind, err := sc.resourceDecoder.Decode([]byte(yamlDoc.Content()), nil, nil)
	if err != nil {
		fileProcessingErrors = appendAndLogNewError(fileProcessingErrors, notK8sResource(yamlDoc.FilePath(), yamlDoc.DocID(), err), sc.logger)
		return false, "", fileProcessingErrors
	}
	if !acceptedK8sTypes.MatchString(groupVersionKind.Kind) {
		sc.logger.Infof("in file: %s, document: %d, skipping object with type: %s", yamlDoc.FilePath(), yamlDoc.DocID(), groupVersionKind.Kind)
		return false, "", fileProcessingErrors
	}
	return true, groupVersionKind.Kind, fileProcessingErrors
}

// given a YAML doc and its resource kind, convert to a slice of K8sObject
//
//gocyclo:ignore
func manifestToK8sObjects(yamlDoc YAMLDocumentIntf, kind string) ([]K8sObject, error) { //nolint:funlen // cases of objects kinds
	objDataBuf := []byte(yamlDoc.Content())
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
	case Service:
		obj := parseService(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Service: obj, Kind: kind})
	case Route:
		obj := parseRoute(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Route: obj, Kind: kind})
	case Ingress:
		obj := parseIngress(bytes.NewReader(objDataBuf))
		res = append(res, K8sObject{Ingress: obj, Kind: kind})
	case List:
		res = parseList(objDataBuf)
	case PodList:
		res = parsePodList(objDataBuf)
	case NamespaceList:
		res = parseNamespaceList(objDataBuf)
	case NetworkpolicyList:
		res = parseNetworkpolicyList(objDataBuf)
	// TODO: support other specific list types, other than PodList and NamespaceList
	default:
		return res, fmt.Errorf("unsupported kind: %s", kind)
	}
	return res, nil
}

const yamlParseBufferSize = 200

// return a map from manifest file paths to bool flag indicating if it is YAML (true) or JSON (false)
func (sc *ResourcesScanner) searchYamlFiles(repoDir string) (map[string]bool, []FileProcessingError) {
	res := map[string]bool{}
	processingErrors := make([]FileProcessingError, 0)
	err := sc.walkFn(repoDir, func(path string, f os.DirEntry, err error) error {
		if err != nil {
			processingErrors = appendAndLogNewError(processingErrors, failedAccessingDir(path, err, path != repoDir), sc.logger)
			if stopProcessing(sc.stopOnError, processingErrors) {
				return err
			}
			return filepath.SkipDir
		}
		if f != nil && !f.IsDir() && yamlSuffix.MatchString(f.Name()) {
			res[path] = true
		} else if sc.includeJSONManifests && f != nil && !f.IsDir() && jsonSuffix.MatchString(f.Name()) {
			res[path] = false
		}
		return nil
	})
	if err != nil {
		sc.logger.Errorf(err, "Error walking directory")
	}
	return res, processingErrors
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

func parseNetworkpolicyList(objDataBuf []byte) []K8sObject {
	if isKind, resList := parseListOfKind(objDataBuf, Networkpolicy); isKind {
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
		checkAndUpdatePodStatusIPsFields(&pl.Items[i])
		res[i] = K8sObject{Pod: &pl.Items[i], Kind: Pod}
	}
	return res, nil
}

// checkAndUpdatePodStatusIPsFields adds fake IP to pod.Status.HostIP or pod.Status.PodIPs if missing
func checkAndUpdatePodStatusIPsFields(rc *v1.Pod) {
	if rc.Status.HostIP == "" {
		rc.Status.HostIP = IPv4LoopbackAddr
	}
	if len(rc.Status.PodIPs) == 0 {
		rc.Status.PodIPs = []v1.PodIP{{IP: IPv4LoopbackAddr}}
	}
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

func convertServiceListTOK8sObjects(svcl *v1.ServiceList) ([]K8sObject, error) {
	res := make([]K8sObject, len(svcl.Items))
	for i := range svcl.Items {
		if isValidKind, err := validateNamespaceAndKind(&svcl.Items[i].Namespace, &svcl.Items[i].Kind, Service); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Service: &svcl.Items[i], Kind: Service}
	}
	return res, nil
}

func convertRouteListTOK8sObjects(rtl *ocroutev1.RouteList) ([]K8sObject, error) {
	res := make([]K8sObject, len(rtl.Items))
	for i := range rtl.Items {
		if isValidKind, err := validateNamespaceAndKind(&rtl.Items[i].Namespace, &rtl.Items[i].Kind, Route); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Route: &rtl.Items[i], Kind: Route}
	}
	return res, nil
}

func convertIngressListTOK8sObjects(ingl *netv1.IngressList) ([]K8sObject, error) {
	res := make([]K8sObject, len(ingl.Items))
	for i := range ingl.Items {
		if isValidKind, err := validateNamespaceAndKind(&ingl.Items[i].Namespace, &ingl.Items[i].Kind, Ingress); !isValidKind {
			return nil, err
		}
		res[i] = K8sObject{Ingress: &ingl.Items[i], Kind: Ingress}
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
	case Service:
		if svclist, ok := parsedList.(*v1.ServiceList); ok {
			return convertServiceListTOK8sObjects(svclist)
		}
	case Route:
		if rtlist, ok := parsedList.(*ocroutev1.RouteList); ok {
			return convertRouteListTOK8sObjects(rtlist)
		}
	case Ingress:
		if inglist, ok := parsedList.(*netv1.IngressList); ok {
			return convertIngressListTOK8sObjects(inglist)
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

//gocyclo:ignore
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
	case Service:
		resList = &v1.ServiceList{}
	case Route:
		resList = &ocroutev1.RouteList{}
	case Ingress:
		resList = &netv1.IngressList{}
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
	checkAndUpdatePodStatusIPsFields(&rc)
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

func parseService(r io.Reader) *v1.Service {
	if r == nil {
		return nil
	}
	rc := v1.Service{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Service); !isValid || err != nil {
		return nil
	}
	return &rc
}

func parseRoute(r io.Reader) *ocroutev1.Route {
	if r == nil {
		return nil
	}
	rc := ocroutev1.Route{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Route); !isValid || err != nil {
		return nil
	}
	return &rc
}

func parseIngress(r io.Reader) *netv1.Ingress {
	if r == nil {
		return nil
	}
	rc := netv1.Ingress{}
	err := yaml.NewYAMLOrJSONDecoder(r, yamlParseBufferSize).Decode(&rc)
	if err != nil {
		return nil
	}
	if isValid, err := validateNamespaceAndKind(&rc.Namespace, &rc.Kind, Ingress); !isValid || err != nil {
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

func stopProcessing(stopOn1stErr bool, errs []FileProcessingError) bool {
	for idx := range errs {
		if errs[idx].IsFatal() || stopOn1stErr && errs[idx].IsSevere() {
			return true
		}
	}

	return false
}

func appendAndLogNewError(errs []FileProcessingError, newErr *FileProcessingError, l logger.Logger) []FileProcessingError {
	logError(l, newErr)
	errs = append(errs, *newErr)
	return errs
}

func logError(l logger.Logger, fpe *FileProcessingError) {
	logMsg := fpe.Error().Error()
	location := fpe.Location()
	if location != "" {
		logMsg = fmt.Sprintf("err : %s %s", location, logMsg)
	}
	if fpe.IsSevere() || fpe.IsFatal() {
		l.Errorf(errors.New(logMsg), "")
	} else {
		l.Warnf(logMsg)
	}
}

func hasWorkloadsOrNetworkPolicies(objects []K8sObject) (hasWl, hasNp bool) {
	var hasWorkloads, hasNetpols bool
	for i := range objects {
		kind := objects[i].Kind
		if kind == Networkpolicy {
			hasNetpols = true
		} else if singleResourceK8sKinds[kind] {
			hasWorkloads = true
		}
	}
	return hasWorkloads, hasNetpols
}
