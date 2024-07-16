/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// unit test for representative_selectors.go file

// matchLabels to be used in selectors
var matchLabels1 = map[string]string{"kubernetes.io/metadata.name": "backend"}
var matchLabels2 = map[string]string{"app": "backend-new"}
var matchLabels3 = map[string]string{"release": "stable", "effect": "NoSchedule"}
var matchLabels4 = map[string]string{"foo.com/managed-state": "managed"}

// requirements to use in selectors
var req1 = v1.LabelSelectorRequirement{Key: "foo.com/managed-state", Operator: v1.LabelSelectorOpIn, Values: []string{"managed"}}
var req2 = v1.LabelSelectorRequirement{Key: "env", Operator: v1.LabelSelectorOpDoesNotExist}
var req3 = v1.LabelSelectorRequirement{Key: "role", Operator: v1.LabelSelectorOpIn, Values: []string{"frontend", "web", "api"}}
var req4 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpNotIn, Values: []string{"b-app", "c-app", "d-app"}}
var req3v = v1.LabelSelectorRequirement{Key: "role", Operator: v1.LabelSelectorOpIn, Values: []string{"web", "api", "frontend"}}
var req4v = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpNotIn, Values: []string{"c-app", "d-app", "b-app"}}
var req5 = v1.LabelSelectorRequirement{Key: "tier", Operator: v1.LabelSelectorOpExists}
var req6 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpNotIn, Values: []string{"x"}}
var req7 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpExists}
var req8 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpIn, Values: []string{"x"}}
var req9 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpDoesNotExist}
var req10 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpNotIn, Values: []string{"b-app", "c-app", "d-app",
	"f-app", "g-app"}}
var req11 = v1.LabelSelectorRequirement{Key: "app", Operator: v1.LabelSelectorOpIn, Values: []string{"b-app", "c-app", "d-app",
	"f-app", "g-app"}}

// selectors to use in the test-cases
var emptySelector = v1.LabelSelector{}
var selector1 = v1.LabelSelector{MatchLabels: matchLabels3, MatchExpressions: []v1.LabelSelectorRequirement{req4, req5}}
var selector2 = &selector1
var selector3 = v1.LabelSelector{MatchLabels: matchLabels4}
var selector4 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req1}}
var selector5 = v1.LabelSelector{MatchLabels: matchLabels2, MatchExpressions: []v1.LabelSelectorRequirement{req2, req3}}
var selector6 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req2, req3}, MatchLabels: matchLabels2}
var selector7 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req2, req3, req4, req5}}
var selector8 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req4, req2, req5, req3}}
var selector9 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req4v, req2, req5, req3v}}
var nsSelector = v1.LabelSelector{MatchLabels: matchLabels1}
var selector10 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req4}}
var selector11 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req6}}
var selector12 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req8}}
var selector13 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req7}}
var selector14 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req9}}
var selector15 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req10}}
var selector16 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req11}}
var selector17 = v1.LabelSelector{MatchExpressions: []v1.LabelSelectorRequirement{req4, req5, req3}}

func TestSelectorsFullMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		testName               string
		realSelector           *v1.LabelSelector
		representativeSelector *v1.LabelSelector
		expectedResult         bool
	}{
		{
			testName:               "selectors_that_point_to_same_reference_are_fully_matched",
			realSelector:           &selector1,
			representativeSelector: selector2,
			expectedResult:         true,
		},
		{
			testName:               "an_empty_real_selectormatches_any_representative_selector",
			realSelector:           &emptySelector,
			representativeSelector: &selector1,
			expectedResult:         true,
		},
		{
			testName:               "matchLabels_selectorand_match_expression_selectorwith_exact_same_requirement_are_full_match",
			realSelector:           &selector3,
			representativeSelector: &selector4,
			expectedResult:         true,
		},
		{
			testName:               "selectors_with_same_requirements_are_full_match",
			realSelector:           &selector5,
			representativeSelector: &selector6,
			expectedResult:         true,
		},
		{
			testName:               "selectors_with_same_requirements_in_different_orders_are_full_match",
			realSelector:           &selector7,
			representativeSelector: &selector8,
			expectedResult:         true,
		},
		{
			testName:               "selectors_with_same_requirements_and_same_values_but_values_in_different_order_are_full_match",
			realSelector:           &selector8,
			representativeSelector: &selector9,
			expectedResult:         true,
		},
		{
			testName:               "an_emptyselectormatches_any_namespace",
			realSelector:           &emptySelector,
			representativeSelector: &nsSelector,
			expectedResult:         true,
		},
		{
			testName:               "selectors_with_same_key_and_operator_but_different_values_are_not_match",
			realSelector:           &selector10,
			representativeSelector: &selector11,
			expectedResult:         false,
		},
		{
			testName:               "selectors_with_same_key_but_different_operators_are_not_match",
			realSelector:           &selector11,
			representativeSelector: &selector12,
			expectedResult:         false,
		},
		{
			testName:               "selectors_with_different_keys_are_not_equiv",
			realSelector:           &selector4,
			representativeSelector: &selector10,
			expectedResult:         false,
		},
		{
			testName:               "selectors_with_same_op_and_key_but_values_lists_contained_in_each_other_are_not_full_match",
			realSelector:           &selector10,
			representativeSelector: &selector15,
			expectedResult:         false,
		},
		{
			testName:               "selectors_with_same_key_and_values_but_different_operators_are_not_full_match",
			realSelector:           &selector15,
			representativeSelector: &selector16,
			expectedResult:         false,
		},
		{
			testName:               "selectors_which_are_contained_in_each_other_are_not_full_match",
			realSelector:           &selector17,
			representativeSelector: &selector8,
			expectedResult:         false,
		},
		{
			testName:               "selectors_which_are_contained_in_each_other_opposite_dir_are_not_full_match",
			realSelector:           &selector8,
			representativeSelector: &selector17,
			expectedResult:         false,
		},
		{
			testName:               "operators_exists_and_in_on_same_key_are_not_equiv_not_match",
			realSelector:           &selector12,
			representativeSelector: &selector13,
			expectedResult:         false,
		},
		{
			testName:               "operators_exists_and_not_in_on_same_key_are_not_equiv_not_match",
			realSelector:           &selector13,
			representativeSelector: &selector15,
			expectedResult:         false,
		},
		{
			testName:               "operators_does_not_exist_and_not_in_on_same_key_are_not_equiv_not_match",
			realSelector:           &selector14,
			representativeSelector: &selector15,
			expectedResult:         false,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			selectorsMatch, err := SelectorsFullMatch(tt.realSelector, tt.representativeSelector)
			require.Empty(t, err, "test %q: err returned from SelectorsFullMatch", tt.testName)
			require.Equal(t, tt.expectedResult, selectorsMatch, "test %q : unexpected result, should be %v", tt.testName, tt.expectedResult)
		})
	}
}
