/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"crypto/sha1" //nolint:gosec // Non-crypto use
	"encoding/hex"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// this file handles checking equality of representative peers' selectors' requirements
// since a representative peer is a peer inferred from a network-policy rule

// areRequirementsEqual given two labelSelector objects, one from a policy rule and the other from a represenatative pod/namespace,
// returns true if:
// 1. both selectors point to same reference (rule and its matching representative pod/ns)
// 2. if the rule's selector is empty (matches all pods/namespaces)
// 3. if the requirements of both rules are equal (same)
func areRequirementsEqual(ruleSelector, repSelector *v1.LabelSelector) (bool, error) {
	if ruleSelector == repSelector { // both label selectors point to same reference
		return true, nil
	}
	// otherwise, check requirements equality
	selector1, err := v1.LabelSelectorAsSelector(ruleSelector)
	if err != nil {
		return false, err
	}
	if selector1.Empty() { // empty rule matches everything
		return true, nil
	}
	selector2, err := v1.LabelSelectorAsSelector(repSelector)
	if err != nil {
		return false, err
	}
	requirements1, _ := selector1.Requirements() // Requirements() returns sorted by key list
	requirements2, _ := selector2.Requirements() // sorted
	if len(requirements1) != len(requirements2) {
		return false, nil
	}
	for i := range requirements1 {
		// requirements1[i].Equal(requirements2[i]) returns false if the values are not in same order
		// (stringslices.Equal returns true only if two slices have same length and same order of items)
		// however, Requirement.string sorts the values, so will compare by string
		if requirements1[i].String() != requirements2[i].String() {
			return false, nil
		}
	}
	return true, nil
}

// VariantFromRequirementsList returns a unique hash key from given labels map, so selectors with same keys, operators and values
// will get same hash key (even if the order of keys was not same in different rules/policies)
func VariantFromLabelsSelector(ls *v1.LabelSelector) (string, error) {
	// since labels.selector.Requirements() returns sorted by key list of requirements, its string used to generate the hash-key
	// this will ensure keeping uniqueness of representative peers in the policy-engine
	selector, err := v1.LabelSelectorAsSelector(ls)
	if err != nil {
		return "", err
	}
	requirements, _ := selector.Requirements()
	// calculating string of requirements (values in a requirement are not sorted internally, requirement.String - sorts them)
	reqStr := ""
	for _, req := range requirements {
		reqStr += req.String()
	}
	return hex.EncodeToString(sha1.New().Sum([]byte(reqStr))), nil //nolint:gosec // Non-crypto use
}
