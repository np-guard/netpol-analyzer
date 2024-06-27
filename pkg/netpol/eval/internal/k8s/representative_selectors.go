/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"crypto/sha1" //nolint:gosec // Non-crypto use
	"encoding/hex"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// this file handles checking match of representative peers' requirements and labels.
// since a representative peer is a peer inferred from a network-policy rule, its pod's and namespace's labels are split into
// matchLabels and requirements of matchExpressions

// ******************************************************************************************************* //
// Checking if a given selector matches (covered by) a representative peer's labels and requirements:
// ---------------------------------------------------------------------
// 1. if the representative peer has only match labels without requirements inferred from matchExpression,
// then labels.selector Matches func is used to
// 2. if the representative selector contains also requirements; then
// check the equivalence of the requirements of the selector and the representative peer's labels and requirements.
//
// to check if a given selector matches the representative peer's requirements (from representative matchExpressions
// and matchLabels):
// loop the selector requirements and compare each to the representative peer's requirements:
// - if the requirement operator is In/ Equals: then representative requirements should contain
// the key with an exact match to the requirement value or also has a requirement with In operator where the values list contains the
// list of the selector's requirement.
// - if the requirement operator is Exists : then the representative requirements must include the key, and it's operator must
// be different from DoesNotExist/ NotIn -> because these are not equivalent with operator : Exists
// (explanation: NotIn selects peer with key with a value not from the list, and all peers without the key (not equivalent with exists))
// - if the requirement operator is DoesNotExist : the the representative labels must not include the key or include
// it with operator DoesNotExist
// - if the requirement operator is NotIn :
// * the operator of the same key should not be Exists (notIn and exists are not equiv; notIn selects also doesNotExist)
// * if the operator of the same key in the representative labels is NotIn; then the list of values of the requirement needs
// to be contained in the !(<values>) list
// or the representative labels should Match the requirement (i.e. key does not exist/ key with value not from the list)
// ******************************************************************************************************* //

// SelectorMatchesRepresentativePeerLabels given a selector from a policy rule and labels and requirements of representative peer;
// check if the selector matches the repreaentative selector created by the peer's labels and requirements
func SelectorMatchesRepresentativePeerLabels(selector labels.Selector, pLabels map[string]string,
	pRequirements []v1.LabelSelectorRequirement) (bool, error) {
	// if the representative peer does not contain any requirements inferred from matchExpression, then return if the selector match
	// the reresentative peer's labels
	if len(pRequirements) == 0 {
		return selector.Matches(labels.Set(pLabels)), nil
	}
	// create selector from the representative peer's labels and requirements
	// and return if the input selector's requirements are a subset of the representative selector's requirements
	peerLabelSelector := v1.LabelSelector{MatchLabels: pLabels, MatchExpressions: pRequirements}
	representativeSelector, err := v1.LabelSelectorAsSelector(&peerLabelSelector)
	if err != nil {
		return false, err
	}
	ruleRequirements, _ := selector.Requirements()
	repPeerRequirements, _ := representativeSelector.Requirements()
	return isRuleRequirementsASubsetOfRepresentativeRequirements(ruleRequirements, repPeerRequirements), nil
}

// isRuleRequirementsASubsetOfRepresentativeRequirements returns if the rule's selector requirements are a subset of
// the representative peer's requirements
func isRuleRequirementsASubsetOfRepresentativeRequirements(ruleReqs, peerReqs labels.Requirements) bool {
	representativeReqsByKey := make(map[string]labels.Requirement, len(peerReqs))
	// put the representative requirements into map from key to its requirement
	for _, repReq := range peerReqs {
		// assuming each key may appear only once in a single selector
		representativeReqsByKey[repReq.Key()] = repReq
	}

	// check if the rule selector's requirements are subset of the representative requirements
	for _, req := range ruleReqs {
		switch req.Operator() {
		case selection.Equals, selection.In:
			if !checkInOperatorMatch(req, representativeReqsByKey) {
				return false
			}
		case selection.Exists:
			if !checkExistsOperatorMatch(req, representativeReqsByKey) {
				return false
			}
		case selection.DoesNotExist:
			if !checkDoesNotExistOperatorMatch(req, representativeReqsByKey) {
				return false
			}
		case selection.NotIn:
			if !checkNotInOperatorMatch(req, representativeReqsByKey) {
				return false
			}
		}
	}
	return true
}

// checkInOperatorMatch : Equals or In requirements means that the key must be in the representative requirements and the value
// list of the requirement must be contained in the representative values list.
func checkInOperatorMatch(req labels.Requirement, representativeReqsMap map[string]labels.Requirement) bool {
	representativeReq, ok := representativeReqsMap[req.Key()]
	if !ok {
		return false
	}
	return (representativeReq.Operator() == selection.In || representativeReq.Operator() == selection.Equals) &&
		listContainments(representativeReq.Values().List(), req.Values().List())
}

// checkExistsOperatorMatch : the representative requirements must include the key, and it's operator must
// be different from DoesNotExist/ NotIn
func checkExistsOperatorMatch(req labels.Requirement, representativeReqsMap map[string]labels.Requirement) bool {
	representativeReq, ok := representativeReqsMap[req.Key()]
	if !ok {
		return false
	}
	return representativeReq.Operator() != selection.DoesNotExist && representativeReq.Operator() != selection.NotIn
}

// checkDoesNotExistOperatorMatch the the representative labels must not include the key or include
// it with operator DoesNotExist only
func checkDoesNotExistOperatorMatch(req labels.Requirement, representativeReqsMap map[string]labels.Requirement) bool {
	if representativeReq, ok := representativeReqsMap[req.Key()]; ok && representativeReq.Operator() != selection.DoesNotExist {
		return false
	}
	return true
}

// checkNotInOperatorMatch: if the selector's requirement is NotIn; then :
// - if representative peer's requirements contain same key with operator NotIn too, its values must contain the req's values list
// - if the representative peer's requirement contains the key with Exists operator, then no match (no equivalence)
// - if the representative peer's requirement contains the key with In/Equals operator, the values of both
// list must not intersect (two-way containment)
func checkNotInOperatorMatch(req labels.Requirement, representativeReqsMap map[string]labels.Requirement) bool {
	representativeReq, ok := representativeReqsMap[req.Key()]
	if ok && representativeReq.Operator() == selection.NotIn &&
		!listContainments(representativeReq.Values().List(), req.Values().List()) {
		return false
	}
	if ok && representativeReq.Operator() == selection.Exists {
		return false
	}
	if ok && (representativeReq.Operator() == selection.Equals || representativeReq.Operator() == selection.In) &&
		(listContainments(req.Values().List(), representativeReq.Values().List()) ||
			listContainments(representativeReq.Values().List(), req.Values().List())) {
		return false
	}
	return true
}

// listContainments gets the two lists of requirements' values; and returns if the second list is contained in the first.
func listContainments(values1, values2 []string) bool {
	// put first values list in a set
	valuesSet := make(map[string]bool, len(values1)) // a set from the representative values list
	for _, val := range values1 {
		valuesSet[val] = true
	}
	// check that all values in the 2nd list are contained in the set
	for _, val := range values2 {
		if !valuesSet[val] {
			return false
		}
	}
	return true
}

// VariantFromRequirementsList returns a unique hash key from given labels map
func VariantFromLabelsSelector(ls v1.LabelSelector) string {
	return hex.EncodeToString(sha1.New().Sum([]byte(fmt.Sprintf("%v", ls)))) //nolint:gosec // Non-crypto use
}
