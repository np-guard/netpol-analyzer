/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"crypto/sha1" //nolint:gosec // Non-crypto use
	"encoding/hex"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// this file handles checking matching of representative peers' selectors' requirements
// with rule selectors from policies
// since a representative peer is a peer inferred from a network-policy rule
// for example, if a policy that captures a real workload `A` has a rule permitting egress connection, with selectors that match a representative peer `B`, 
// we need to capture this match, and thus infer the exposure connectivity from `A` to `B`

// SelectorsFullMatch given two labelSelector objects, one from a policy rule and the other from a representative pod,
// returns true if:
// 1. both selectors point to same reference (rule and its matching representative pod/ns)
// 2. if the rule's selector is empty (matches all pods/namespaces)
// 3. if the requirements of both rules are equal (same)
// i.e. checks if the selector from the policy rule fully matches the selector of the representative peer
// note that : for non-empty selectors that partly match/ contained in each other the func returns false
func SelectorsFullMatch(ruleSelector, repSelector *v1.LabelSelector) (bool, error) {
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
		str1 := requirements1[i].String()
		str2 := requirements2[i].String()

		// handling special case of one requirement has `In` operator with 1 value, and other requirement has "=" operator (from matchLabel)
		// for example : req1 := (app in x), req2 := (app=x) >> we expect a full match, however,
		// labels pkg treats them as different requirements
		// i.e. requirements1[i].Equal(requirements2[i]) and requirements1[i].String() != requirements2[i].String() return false in this case
		// requirement.String() : returns <key>=<values> string for "Equals" operator and returns (<key> in (<values));
		// so, in case on requirement is "in" with one value only , will convert its string to the <key>=<values> format to get correct result
		if newStr1 := handleRequirementWithInOpAndSingleValue(requirements1[i]); newStr1 != "" {
			str1 = newStr1
		}
		if newStr2 := handleRequirementWithInOpAndSingleValue(requirements2[i]); newStr2 != "" {
			str2 = newStr2
		}
		if str1 != str2 {
			return false, nil
		}
	}
	return true, nil
}

// handleRequirementWithInOpAndSingleValue returns a <key>=<val> string format if the input Requirement is with In operator and single value
func handleRequirementWithInOpAndSingleValue(req labels.Requirement) string {
	if req.Operator() == selection.In && len(req.Values()) == 1 {
		return req.Key() + "=" + req.Values().List()[0]
	}
	return ""
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
		currentStr := req.String()
		// for special case of a requirement with In operator and only one value, convert its string to "key=val" (instead of key in (val))
		// example: so only one representative peer is generated for both rules : app In [x] and app=x
		// (see tests/test_exposure_different_but_equiv_rules)
		if newStr := handleRequirementWithInOpAndSingleValue(req); newStr != "" {
			currentStr = newStr
		}
		reqStr += currentStr
	}
	return hex.EncodeToString(sha1.New().Sum([]byte(reqStr))), nil //nolint:gosec // Non-crypto use
}
