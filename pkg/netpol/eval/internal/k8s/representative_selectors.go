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

// this file handles checking matching of representative peers' selectors' requirements
// with rule selectors from policies
// since a representative peer is a peer inferred from a network-policy rule

// doSelectorsMatch given two labelSelector objects, one from a policy rule and the other from a representative pod,
// returns true if:
// 1. both selectors point to same reference (rule and its matching representative pod/ns)
// 2. if the rule's selector is empty (matches all pods/namespaces)
// 3. if the requirements of both rules are equal (same)
// i.e. checks if the selector from the policy rule matches the selector of the representative peer
func doSelectorsMatch(ruleSelector, repSelector *v1.LabelSelector) (bool, error) {
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
	// Requirements() returns sorted by key list;
	// since `v1.LabelSelectorAsSelector` builds a new `labels.selector` by using `Requirements.Add` which sorts the requirements slice by key.
	// and `Requirements()` returns this sorted list
	// links:
	// v1.LabelSelectorAsSelector:
	// https://github.com/kubernetes/apimachinery/blob/dc7e034c86479d49be4b0eefad307621e10caa0e/pkg/apis/meta/v1/helpers.go#L34
	// Requirements.Add : https://github.com/kubernetes/apimachinery/blob/d7e1c5311169d5ece2db0ae0118066859aa6f7d8/pkg/labels/selector.go#L373
	requirements1, _ := selector1.Requirements() // sorted
	requirements2, _ := selector2.Requirements() // sorted
	if len(requirements1) != len(requirements2) {
		return false, nil
	}
	for i := range requirements1 {
		// requirements1[i].Equal(requirements2[i]) returns false if the values are not in same order
		// (stringslices.Equal returns true only if two slices have same length and same order of items)
		// however, `Requirement.String` sorts the values using `safeSort`, so will compare by string
		// link to Requirement.String() :
		// https://github.com/kubernetes/apimachinery/blob/d7e1c5311169d5ece2db0ae0118066859aa6f7d8/pkg/labels/selector.go#L310
		if requirements1[i].String() != requirements2[i].String() {
			return false, nil
		}
	}
	return true, nil
}

// VariantFromLabelsSelector returns a unique hash key from given labelSelector, so selectors with same keys, operators and values
// will get same hash key (even if the order of keys was not same in different rules/policies)
func VariantFromLabelsSelector(ls *v1.LabelSelector) (string, error) {
	// since labels.selector.Requirements() returns sorted by key list of requirements, its string used to generate the hash-key
	// this will ensure keeping uniqueness of representative peers in the policy-engine
	selector, err := v1.LabelSelectorAsSelector(ls)
	if err != nil {
		return "", err
	}
	requirements, _ := selector.Requirements()
	// calculating string of requirements (`values` list in a requirement is not sorted internally, Requirement.String() - sorts it)
	reqStr := ""
	for _, req := range requirements {
		reqStr += req.String()
	}
	return hex.EncodeToString(sha1.New().Sum([]byte(reqStr))), nil //nolint:gosec // Non-crypto use
}
