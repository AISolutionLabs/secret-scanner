package detect

// matcher is a dense Aho-Corasick automaton over lowercase ASCII bytes. It
// finds every occurrence of every rule keyword in a single pass, replacing
// one strings.Index sweep per keyword per fragment.
type matcher struct {
	next [][256]int32
	out  [][]int32 // keyword indices ending at each state
	lens []int
}

func newMatcher(keys []string) *matcher {
	m := &matcher{next: make([][256]int32, 1), out: make([][]int32, 1), lens: make([]int, len(keys))}
	for i := range m.next[0] {
		m.next[0][i] = -1
	}
	for ki, k := range keys {
		m.lens[ki] = len(k)
		s := int32(0)
		for i := 0; i < len(k); i++ {
			c := k[i]
			if m.next[s][c] == -1 {
				var row [256]int32
				for j := range row {
					row[j] = -1
				}
				m.next = append(m.next, row)
				m.out = append(m.out, nil)
				m.next[s][c] = int32(len(m.next) - 1)
			}
			s = m.next[s][c]
		}
		m.out[s] = append(m.out[s], int32(ki))
	}
	// BFS to fill failure transitions into a full DFA.
	fail := make([]int32, len(m.next))
	queue := make([]int32, 0, len(m.next))
	for c := 0; c < 256; c++ {
		if t := m.next[0][c]; t == -1 {
			m.next[0][c] = 0
		} else {
			fail[t] = 0
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		m.out[s] = append(m.out[s], m.out[fail[s]]...)
		for c := 0; c < 256; c++ {
			t := m.next[s][c]
			if t == -1 {
				m.next[s][c] = m.next[fail[s]][c]
				continue
			}
			fail[t] = m.next[fail[s]][c]
			queue = append(queue, t)
		}
	}
	return m
}

// find returns, per keyword index, the start offsets of its occurrences in
// lower (which must already be ASCII-lowercased).
func (m *matcher) find(lower string) [][]int {
	res := make([][]int, len(m.lens))
	s := int32(0)
	for i := 0; i < len(lower); i++ {
		s = m.next[s][lower[i]]
		for _, k := range m.out[s] {
			res[k] = append(res[k], i-m.lens[k]+1)
		}
	}
	return res
}
