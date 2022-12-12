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
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

const (
	cacheHitsLog      = "cacheHitsLog.txt"
	writeOnlyFileMode = 0644
	defaultCacheSize  = 500
	minCacheSize      = 10
	maxCacheSize      = 10000
)

type evalCache struct {
	sync.RWMutex                                  // protects only ownerToPods; lru.Cache is goroutine safe, debug-only fields are ignored
	ownerToPods    map[string]map[string]struct{} // map from owner key to its associated pods map
	cacheHitsCount int                            // for testing
	debug          bool
	cache          *lru.Cache
}

// newEvalCache returns a new EvalCache with an empty initial state, of default size
func newEvalCache() *evalCache {
	return newEvalCacheWithSize(defaultCacheSize)
}

// newEvalCacheWithSize returns a new EvalCache with an empty initial state
func newEvalCacheWithSize(size int) *evalCache {
	cacheSize := defaultCacheSize
	if size >= minCacheSize && size <= maxCacheSize {
		cacheSize = size
	} else {
		fmt.Printf("Warning: newEvalCache requested cached size is not within supported range. Using default cache size instead.")
	}

	cache, err := lru.New(cacheSize)
	if err != nil {
		cache = nil // disable caching on error
	}
	// for debugging
	os.Remove(cacheHitsLog)

	return &evalCache{
		cache:       cache,
		debug:       true,
		ownerToPods: make(map[string]map[string]struct{}),
	}
}

func getPodOwnerKey(p *k8s.Pod) string {
	return strings.Join([]string{p.Namespace, p.Owner.Name, p.Owner.Variant}, string(types.Separator))
}

// TODO: currently supporting only connections between two pods with owners for caching
// keyPerConnection: return string value of key per input connection
func (ec *evalCache) keyPerConnection(src, dst k8s.Peer, protocol, port string) string {
	if src.PeerType() == k8s.PodType && dst.PeerType() == k8s.PodType {
		if src.GetPeerPod().Owner.Name != "" && dst.GetPeerPod().Owner.Name != "" {
			srcKey := getPodOwnerKey(src.GetPeerPod())
			dstKey := getPodOwnerKey(dst.GetPeerPod())
			return strings.Join([]string{srcKey, dstKey, protocol, port}, string(types.Separator))
		}
	}
	return ""
}

func (ec *evalCache) hasConnectionResult(src, dst k8s.Peer, protocol, port string) (bool, bool) {
	if ec.cache == nil {
		return false, false
	}
	connectionKey := ec.keyPerConnection(src, dst, protocol, port)
	if connectionKey == "" {
		return false, false
	}
	if res, ok := ec.cache.Get(connectionKey); ok {
		if ec.debug {
			ec.cacheHitsCount += 1
			f, _ := os.OpenFile(cacheHitsLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, writeOnlyFileMode)
			cacheHitLine := fmt.Sprintf("cache hit on key: %v \n", connectionKey)
			_, err := f.WriteString(cacheHitLine)
			if err != nil {
				fmt.Printf("error WriteString: %v", err)
			}
		}
		return true, res.(bool)
	}
	return false, false
}

func (ec *evalCache) addConnectionResult(src, dst k8s.Peer, protocol, port string, res bool) {
	if ec.cache == nil {
		return
	}
	connectionKey := ec.keyPerConnection(src, dst, protocol, port)
	if connectionKey == "" {
		return
	}
	ec.cache.Add(connectionKey, res)
}

func (ec *evalCache) clear() {
	if ec.cache == nil {
		return
	}
	ec.cache.Purge()

	ec.Lock()
	defer ec.Unlock()
	ec.ownerToPods = make(map[string]map[string]struct{})
}

func (ec *evalCache) addPod(p *k8s.Pod, podName string) {
	podKey := getPodOwnerKey(p)

	ec.Lock()
	defer ec.Unlock()
	if _, ok := ec.ownerToPods[podKey]; !ok {
		ec.ownerToPods[podKey] = make(map[string]struct{})
	}
	ec.ownerToPods[podKey][podName] = struct{}{}
}

func (ec *evalCache) deletePod(p *k8s.Pod, podName string) {
	podKey := getPodOwnerKey(p)

	ec.Lock()
	defer ec.Unlock()
	if _, ok := ec.ownerToPods[podKey]; ok {
		// delete pod from its associated owner at ownerToPods map
		delete(ec.ownerToPods[podKey], podName)
	}
	// check if no pods are left for this owner
	if len(ec.ownerToPods[podKey]) == 0 {
		// delete cache entries with this pod owner
		ec.deleteWorkload(podKey)
		// delete owner from ownerToPods map
		delete(ec.ownerToPods, podKey)
	}
}

// deleteWorkload: delete cache keys containing the workload key string in a cached connection
func (ec *evalCache) deleteWorkload(key string) {
	cacheKeys := ec.cache.Keys()
	for _, cacheKey := range cacheKeys {
		if strings.Contains(cacheKey.(string), key) {
			ec.cache.Remove(cacheKey)
		}
	}
}
