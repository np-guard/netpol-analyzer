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

// SelectorsFullMatch checks if there is a match between two input labelSelector objects,
// one from a policy rule and the other from a representative pod.
// for example, if a policy that captures a real workload `A` has a rule permitting egress connection,
// with selectors that match a representative peer `B`, we need to capture this match,
// and thus infer the exposure connectivity from `A` to `B`.
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
	ruleSelectorConverted, err := v1.LabelSelectorAsSelector(ruleSelector)
	if err != nil {
		return false, err
	}
	if ruleSelectorConverted.Empty() { // empty rule matches everything
		// returning true, so we can capture the connection with this rule and add it to the exposure connection of the representative peer.
		// (even if there is a line in the report with connections to entire-cluster, the rep-per connections will
		// be a union of its own exposure and the ones from the entire-cluster).
		// note that:
		// 1. if the connection to this representative peer is contained in the connection to entire-cluster; we will not
		// see this representative peer in the output (see example: tests/test_matched_and_unmatched_rules)
		// 2. if the representative peer's selectors are contained (not equal) in another's representative peer selectors, the connection of the
		// other representative-peer will not be captured to this representative peer also
		// (see example: tests/test_exposure_with_different_rules_4)
		return true, nil
	}
	repSelectorConverted, err := v1.LabelSelectorAsSelector(repSelector)
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
	ruleRequirements, _ := ruleSelectorConverted.Requirements() // sorted
	repRequirements, _ := repSelectorConverted.Requirements()   // sorted
	if len(ruleRequirements) != len(repRequirements) {
		return false, nil
	}
	for i := range ruleRequirements {
		// ruleRequirements[i].Equal(repRequirements[i]) returns false if the values are not in same order
		// (stringslices.Equal returns true only if two slices have same length and same order of items)
		// however, `Requirement.String` sorts the values using `safeSort`, so will compare by string
		// link to Requirement.String() :
		// https://github.com/kubernetes/apimachinery/blob/d7e1c5311169d5ece2db0ae0118066859aa6f7d8/pkg/labels/selector.go#L310
		ruleRequirementsStr := ruleRequirements[i].String()
		repRequirementsStr := repRequirements[i].String()

		// handling special case of one requirement has `In` operator with 1 value, and other requirement has "=" operator (from matchLabel)
		// for example : req1 := (app in x), req2 := (app=x) >> we expect a full match, however,
		// labels pkg treats them as different requirements
		// i.e. ruleRequirements[i].Equal(repRequirements[i]) and ruleRequirements[i].String() == repRequirements[i].String() return false
		// requirement.String() : returns <key>=<values> string for "Equals" operator and returns (<key> in (<values));
		// so, in case on requirement is "in" with one value only, will convert its string to the <key>=<values> format to get correct result
		if newRuleRequirementsStr := handleRequirementWithInOpAndSingleValue(ruleRequirements[i]); newRuleRequirementsStr != "" {
			ruleRequirementsStr = newRuleRequirementsStr
		}
		if newRepRequirementsStr := handleRequirementWithInOpAndSingleValue(repRequirements[i]); newRepRequirementsStr != "" {
			repRequirementsStr = newRepRequirementsStr
		}
		if ruleRequirementsStr != repRequirementsStr {
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

// UniqueKeyFromLabelsSelector returns a unique hash key from given labelSelector, so selectors with same keys, operators and values
// will get same hash key (even if the order of keys was not same in different rules/policies)
func UniqueKeyFromLabelsSelector(ls *v1.LabelSelector) (string, error) {
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
