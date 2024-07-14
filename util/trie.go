package util

type TrieNode struct {
	children map[rune]*TrieNode
	isEnd    bool
}

type Trie struct {
	root *TrieNode
}

func NewTrie() *Trie {
	return &Trie{root: &TrieNode{children: make(map[rune]*TrieNode)}}
}

func (t *Trie) Insert(word string) {
	node := t.root
	for _, char := range word {
		if _, ok := node.children[char]; !ok {
			node.children[char] = &TrieNode{children: make(map[rune]*TrieNode)}
		}
		node = node.children[char]
	}
	node.isEnd = true
}

func (t *Trie) Search(word string) bool {
	node := t.root
	for _, char := range word {
		if _, ok := node.children[char]; !ok {
			return false
		}
		node = node.children[char]
	}
	return node.isEnd
}

func (t *Trie) ShortestPrefix(word string) (string, string) {
	prefixLen := 1
	node := t.root
	for _, char := range word {
		if _, ok := node.children[char]; !ok {
			return "", ""
		}
		if len(node.children[char].children) > 1 {
			prefixLen += 1
		}
		node = node.children[char]
	}
	return word[:prefixLen], word[prefixLen:]
}
