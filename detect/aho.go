package detect

// Aho-Corasick over bytes, the multi-pattern search behind the maintained
// term list. It is written out here rather than pulled in as a dependency:
// the automaton is a hundred lines, and the forward path must not depend on
// map iteration order, which is easier to guarantee in code one can read.
//
// The automaton is built once in NewTerms and is read-only afterwards, so it
// is safe for concurrent use. Determinism comes from the child order being
// insertion order, which follows the order of the configured terms, and from
// the failure links of a node depending only on strictly shallower nodes.

// acNode is one trie node. kids maps the next byte to the child index, order
// repeats the same bytes in insertion order so the breadth-first pass and the
// output sets never depend on map iteration.
type acNode struct {
	kids  map[byte]int32
	order []byte
	fail  int32
	out   []int32
}

// ahoCorasick is a compiled set of literal patterns.
type ahoCorasick struct {
	nodes []acNode
	plen  []int
}

// newAho compiles pats. Empty patterns are accepted but never reported.
func newAho(pats []string) *ahoCorasick {
	ac := &ahoCorasick{nodes: make([]acNode, 1, len(pats)*8+1), plen: make([]int, len(pats))}
	for i, p := range pats {
		ac.plen[i] = len(p)
		if p == "" {
			continue
		}
		cur := int32(0)
		for k := 0; k < len(p); k++ {
			b := p[k]
			next, ok := ac.nodes[cur].kids[b]
			if !ok {
				ac.nodes = append(ac.nodes, acNode{})
				next = int32(len(ac.nodes) - 1)
				if ac.nodes[cur].kids == nil {
					ac.nodes[cur].kids = make(map[byte]int32, 4)
				}
				ac.nodes[cur].kids[b] = next
				ac.nodes[cur].order = append(ac.nodes[cur].order, b)
			}
			cur = next
		}
		ac.nodes[cur].out = append(ac.nodes[cur].out, int32(i))
	}

	// Breadth-first over the trie: the depth-one nodes fail to the root, every
	// deeper node fails to the state reached by walking its byte from the
	// failure state of its parent.
	queue := make([]int32, 0, len(ac.nodes))
	for _, b := range ac.nodes[0].order {
		c := ac.nodes[0].kids[b]
		ac.nodes[c].fail = 0
		queue = append(queue, c)
	}
	for i := 0; i < len(queue); i++ {
		u := queue[i]
		for _, b := range ac.nodes[u].order {
			v := ac.nodes[u].kids[b]
			ac.nodes[v].fail = ac.step(ac.nodes[u].fail, b)
			if f := ac.nodes[v].fail; len(ac.nodes[f].out) > 0 {
				ac.nodes[v].out = append(ac.nodes[v].out, ac.nodes[f].out...)
			}
			queue = append(queue, v)
		}
	}
	return ac
}

// step follows byte b from state, falling back along the failure links.
func (ac *ahoCorasick) step(state int32, b byte) int32 {
	for {
		if n, ok := ac.nodes[state].kids[b]; ok {
			return n
		}
		if state == 0 {
			return 0
		}
		state = ac.nodes[state].fail
	}
}

// find calls emit for every occurrence of every pattern in text, in order of
// end position. Occurrences may overlap; the caller resolves that.
func (ac *ahoCorasick) find(text string, emit func(start, end, pattern int)) {
	if len(ac.nodes) < 2 {
		return
	}
	state := int32(0)
	for i := 0; i < len(text); i++ {
		state = ac.step(state, text[i])
		for _, p := range ac.nodes[state].out {
			n := ac.plen[p]
			if n == 0 {
				continue
			}
			emit(i+1-n, i+1, int(p))
		}
	}
}
