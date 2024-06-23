/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file handles converting and checking match of representative peers' labels.
// since a representative peer is a peer inferred from a network-policy rule, its pod's and namespace's labels
// may have special labels cases, and thus need to be handled differently from usual accepted k8s labels (regular <key>:<value>).

// examples:
// 1. if we have a policy rule with:
// - podSelector:
//     matchExpressions:
//             {key: app, operator: Exists}
//
// this rule will be converted when generating a matching representative peer.
// the representative peer's pod will has an `app: <exists>` in its podLabels map.
//
// 2. if we have a policy rule with:
// - podSelector:
//     matchExpressions:
//                 {key: name, operator: In, values: [payroll, web]}
// two different representative peers will be generated from this PodSelector; one with pod label {name:payroll} ,
// and the second with pod label {name:web}

// ///////////////////////////////////////////
const (
	notSuffix = ")"
	comma     = ","
)

// labelsSet is an alias for labels map (map[string]string)
type labelsSet map[string]string

// copyLabelsSet - helping func, copies the current labelsSet (map of labels)
func (ls labelsSet) copyLabelsSet() labelsSet {
	res := make(labelsSet, len(ls))
	for k, v := range ls {
		res[k] = v
	}
	return res
}

// RepresentativePeerLabels contains the namespace and pod labels for generating a single representative peer
type RepresentativePeerLabels struct {
	// NsLabels the labels of the namespace of the representative peer
	NsLabels labelsSet
	// PodLabels the labels of the pod of the representative peer
	PodLabels labelsSet
	// UnusualPodLabelsFlag indicates if the labels set inferred from a podSelector that contains
	// matchExpression with operator:NotIn, Exists, DoesNotExist - which require special handling
	UnusualPodLabelsFlag bool
	// UnusualNsLabelsFlag indicates if the labels set inferred from a namespaceSelector that contains
	// matchExpression with operator:NotIn, Exists, DoesNotExist - which require special handling
	UnusualNsLabelsFlag bool
}

// LabelsPairsList list of pairs of matching labels which were inferred from combinations of policy rules' selectors,
// each pair in the list represents labels of a single representative peer
// i.e. a representative peer will be generated for each item in the list
type LabelsPairsList []RepresentativePeerLabels

// ****************************************************************** //
// Converting selector to list of labels sets [](map[string]string)):
// ------------------------------------------------------------------
// - selector with "matchLabels", is converted to one map of labels since "matchLabels" rule can only be used for exact matching
// with all of its <key>:<val> labels.
// - selector with "matchExpression" is set-based matching so it may be converted to number of maps, also, might need special handling
// according to the operator, as following:
//              * operator In: selector will be converted to number of sets (of <key>:<val>) equal to length of requirement's values list;
//                           each set will contain the key and a single value from the values list.
//              * operator Exists : selector will be converted to a one set with <key>:"<exists>"
//              * operator DoesNotExist: selector will be converted to one set with <key>:"<does-not-exist>"
//              * operator NotIn :selector will be converted to one set with <key>: "!(<values>)" (the list of values joined)
//
// *** a selector with multiple matchLabels/matchExpressions : the converted sets of each will be And-ed.(all
// combinations will be generated)
//  *************************************************************************** //

// ConvertSelectorsToLabelsCombinations gets selectors pair (podSelector and nsSelector)
// and converts it to a list of all pairs of matching labels maps;
// by translating the two selectors to all possible requirements and pairing all relevant combinations.
//
// for example :
// single rule selectors: {NsSelector: {key: env, operator: In, values:(env-1,env-2)},
//
//	PodSelector: {key: app, operator: In, values:(app1,app2)}}
//
// will result in 4 combinations of of representative peers labels as following:
// 1. {NsLabels: {env: env-1}, PodLabels:{app: app1}}
// 2. {NsLabels: {env: env-1}, PodLabels:{app: app2}}
// 3. {NsLabels: {env: env-2}, PodLabels:{app: app1}}
// 4. {NsLabels: {env: env-2}, PodLabels:{app: app2}}
func ConvertSelectorsToLabelsCombinations(ruleSelectors *SingleRuleSelectors) LabelsPairsList {
	res := LabelsPairsList{}
	nsLabelsCombinations, unusualNsLabels := convertSingleSelectorToItsMaps(ruleSelectors.NsSelector)
	podLabelsCombinations, unusualPodLabels := convertSingleSelectorToItsMaps(ruleSelectors.PodSelector)
	// create all possible combinations of matching nsLabels and podLabels
	for _, nsLabels := range nsLabelsCombinations {
		for _, podLabels := range podLabelsCombinations {
			representativePeerLabels := RepresentativePeerLabels{
				NsLabels:             nsLabels,
				PodLabels:            podLabels,
				UnusualPodLabelsFlag: unusualPodLabels,
				UnusualNsLabelsFlag:  unusualNsLabels,
			}
			res = append(res, representativePeerLabels)
		}
	}
	return res
}

// convertSingleSelectorToItsMaps gets a single selector and converts it to its all possible matching labels sets
//
// for example: a selector with:
// {key: name, operator: In, values: [payroll, web]}
// will be converted to two different maps, one with {name:payroll} , and the other {name:web}
//
// more details above (Converting selector to list of labels sets)
func convertSingleSelectorToItsMaps(selector labels.Selector) ([]labelsSet, bool) {
	// all requirements of the given selector
	requirements, _ := selector.Requirements()
	if len(requirements) == 0 { // an empty set
		return []labelsSet{{}}, false
	}
	// res will contain all different combinations conducted from the different requirements
	res := []labelsSet{{}}
	unusualLabels := false // to indicate requirements of Exists, DoesNotExist or NotIn

	for _, req := range requirements {
		// newResult will contain the current res with all the new combinations from current requirement
		// (used with In operator as more than one set may be added for its values)
		newResult := make([]labelsSet, 0)

		switch req.Operator() {
		case selection.Equals:
			// requirement with Equals operator is inferred from single matchLabels <key>:<val>,(exactly one value for one key)
			// iterate the current res (maps created till now) and add this requirement to each set in the result
			res = appendKeyAndValueToAllSetsInAList(res, req.Key(), req.Values().List()[0])
		case selection.In:
			// inferred from matchExpression with In operator
			// loop the possible values in the requirement, each value will be a part of a different labelsSet.
			// so for each value: copy the current res (previous labelsSets from the previous requirements) and add the
			// <req.key>:<valFromValues>  (each set with a different value from this values list)
			// i.e. new sets will be added to the list
			for _, val := range req.Values().List() {
				for _, ls := range res {
					newLs := ls.copyLabelsSet()
					newLs[req.Key()] = val
					newResult = append(newResult, newLs)
				}
			}
			res = newResult
		case selection.Exists:
			// inferred from matchExpression with Exists, iterate current result and add key:"<exists>" to each set
			res = appendKeyAndValueToAllSetsInAList(res, req.Key(), common.ExistsVal)
			unusualLabels = true
		case selection.DoesNotExist:
			// inferred from matchExpression with DoesNotExist, iterate current result and add key:"<does-not-exist>" to each set
			res = appendKeyAndValueToAllSetsInAList(res, req.Key(), common.DoesNotExistVal)
			unusualLabels = true
		case selection.NotIn:
			// inferred from matchExpression with NotIn, iterate current result and add key:"!(values)" to each set
			res = appendKeyAndValueToAllSetsInAList(res, req.Key(), common.NotPrefix+strings.Join(req.Values().List(), comma)+notSuffix)
			unusualLabels = true
		}
	}
	return res, unusualLabels
}

// appendKeyAndValueToAllSetsInAList iterates given list of sets and adds given key:val to each set
func appendKeyAndValueToAllSetsInAList(listOfMaps []labelsSet, key, val string) (res []labelsSet) {
	for _, ls := range listOfMaps {
		ls[key] = val
		res = append(res, ls)
	}
	return res
}

// ******************************************************************************************************* //
// Checking if a given selector matches a representative peer's labels :
// ---------------------------------------------------------------------
// 1. if the representative labels have no unusual requirements, then labels.selector Matches func is used to
// compare between the selector and representative peer's labels.
// 2. if the representative selector contains labels with special/unusual requirements
// (which are formed while converting policy rules); then
// check the equivalence of the requirements of the selector and the representative peer's labels.
//
// to check if a given selector matches the representative labels:
// loop the selector requirements and compare each to the representative labels as following:
// - if the requirement operator is In/ Equals: then representative labels should contain
// the key with an exact match to the requirement value/s.
// - if the requirement operator is Exists : then the representative labels must include the key, and it's value must
// be different from <does-not-exist>/ !(<values>) -> because these are not equivalent with operator : Exists
// (explanation: NotIn selects peer with key with a value not from the list, and all peers without the key (not equivalent with exists))
// - if the requirement operator is DoesNotExist : the the representative labels must not include the key or include
// it with value : <does-not-exist>
// - if the requirement operator is NotIn :
// * the val of the same key should not be <exists> (notIn and exists are not equiv; notIn selects also doesNotExist)
// * if the val of the same key in the representative labels is !(<values>);
// then the list of values of the requirement needs to be contained in the !(<values>) list
// or the representative labels should Match the requirement (i.e. key does not exist/ key with value not from the list)
// ******************************************************************************************************* //

// SelectorMatchesRepresentativePeerLabels given a selector from a policy rule and labelsSet of representative peer;
// check if the selector matches the labels, considering the cases of unusual labels values of a generated representative peer
//
//gocyclo:ignore
func SelectorMatchesRepresentativePeerLabels(selector labels.Selector, pLabels labelsSet, hasUnusualLabels bool) bool {
	if !hasUnusualLabels {
		return selector.Matches(labels.Set(pLabels))
	}
	// check if given selector requirements, matches the labels of the representative peer
	selectorReqs, _ := selector.Requirements()
	for _, req := range selectorReqs {
		val, ok := pLabels[req.Key()]
		switch req.Operator() {
		case selection.Equals, selection.In:
			// Equals or In requirements means that the labels map must contain the key with a value from the values list of the requirement.
			if !ok || (ok && !req.Matches(labels.Set(pLabels))) {
				return false
			}
		case selection.Exists:
			// if the requirement for a key in a policy rule selector is to exist, then it must appear in the representative peer's labels
			// and its value must not be <does-not-exist> or !(<values>)
			if !ok || val == common.DoesNotExistVal || strings.HasPrefix(val, common.NotPrefix) {
				return false
			}
		case selection.DoesNotExist:
			// if requirement is does not exist, so if the key is in the representative labels it must have the <does-not-exist> val,
			// otherwise no match
			if ok && val != common.DoesNotExistVal {
				return false
			}
		case selection.NotIn:
			// if the selector requirement is NotIn, a representative peer with label: req.Key : !(values), the values list should contain the
			// req.Values.List , if the value is <exists> then it is not a match,
			// otherwise the requirement should match given labels
			// (key does not exist or has any value which is not in the req.Values.List)
			if (ok &&
				strings.HasPrefix(val, common.NotPrefix) && !representativeValListContainsRequirementValList(val, req.Values().List())) ||
				val == common.ExistsVal ||
				!req.Matches(labels.Set(pLabels)) {
				return false
			}
		}
	}
	return true
}

// representativeValListContainsRequirementValList gets the values of the representative peer NotIn label (as string)
// and a list of a requirement values; returns if the list is contained in the representative values.
func representativeValListContainsRequirementValList(representativeNotInVal string, requirementValues []string) bool {
	// split the representative string to the values and put theem in a set
	repValList := strings.Split(representativeNotInVal[2:len(representativeNotInVal)-1], comma)
	repValsSet := make(map[string]bool, len(repValList)) // a set from the representative values list
	for _, val := range repValList {
		repValsSet[val] = true
	}
	// check that all values in the requirement's list are contained in the set
	for _, val := range requirementValues {
		if !repValsSet[val] {
			return false
		}
	}
	return true
}
