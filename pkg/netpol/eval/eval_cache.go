// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package eval

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

const (
	cacheHitsLog      = "cacheHitsLog.txt"
	writeOnlyFileMode = 0644
)

type EvalCache struct {
	cacheByWorkloads map[string]bool // map keys: "src/dst/protocol/port" as workloads (including variant per workload)
	cacheHitsCount   int             // for testing
	debug            bool
}

// NewEvalCache returns a new EvalCache with an empty initial state
func NewEvalCache() *EvalCache {
	return &EvalCache{
		cacheByWorkloads: map[string]bool{},
		debug:            true,
	}
}

func getPodOwnerKey(p *k8s.Pod) string {
	return strings.Join([]string{p.Namespace, p.Owner.Name, p.Owner.Variant}, string(types.Separator))
}

func (ec *EvalCache) keyPerConnection(src, dst *k8s.Peer, protocol, port string) string {
	if src.PeerType == k8s.PodType && dst.PeerType == k8s.PodType {
		if src.Pod.Owner.Name != "" && dst.Pod.Owner.Name != "" {
			srcKey := getPodOwnerKey(src.Pod)
			dstKey := getPodOwnerKey(dst.Pod)
			return strings.Join([]string{srcKey, dstKey, protocol, port}, string(types.Separator))
		}
	}
	return ""
}

func (ec *EvalCache) hasConnectionResult(src, dst *k8s.Peer, protocol, port string) (bool, bool) {
	connectionKey := ec.keyPerConnection(src, dst, protocol, port)
	if connectionKey == "" {
		return false, false
	}
	if res, ok := ec.cacheByWorkloads[connectionKey]; ok {
		if ec.debug {
			ec.cacheHitsCount += 1
			f, _ := os.OpenFile(cacheHitsLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, writeOnlyFileMode)
			cacheHitLine := fmt.Sprintf("cache hit on key: %v \n", connectionKey)
			_, err := f.WriteString(cacheHitLine)
			if err != nil {
				fmt.Printf("error WriteString: %v", err)
			}
		}
		return true, res
	}
	return false, false
}

func (ec *EvalCache) addConnectionResult(src, dst *k8s.Peer, protocol, port string, res bool) {
	connectionKey := ec.keyPerConnection(src, dst, protocol, port)
	if connectionKey == "" {
		return
	}
	ec.cacheByWorkloads[connectionKey] = res
}
