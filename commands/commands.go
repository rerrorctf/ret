package commands

type CommandFunc func([]string)
type CommandHelpFunc func() string

type Argument struct {
	Name     string
	Optional bool
	List     bool
	Default  string
	Override bool
}

type Command struct {
	Name      string
	Emoji     string
	Func      CommandFunc
	Help      CommandHelpFunc
	Url       string
	Arguments []Argument
	SeeAlso   []string
}

type CommandTrieNode struct {
	children map[rune]*CommandTrieNode
	isEnd    bool
	command  *Command
}

type CommandTrie struct {
	root *CommandTrieNode
}

func NewTrie() *CommandTrie {
	return &CommandTrie{root: &CommandTrieNode{children: make(map[rune]*CommandTrieNode)}}
}

func (t *CommandTrie) Insert(word string, command *Command) {
	node := t.root
	for _, char := range word {
		if _, ok := node.children[char]; !ok {
			node.children[char] = &CommandTrieNode{children: make(map[rune]*CommandTrieNode)}
		}
		node = node.children[char]
	}
	node.isEnd = true
	node.command = command
}

func (t *CommandTrie) Search(word string) (bool, *Command) {
	node := t.root
	for _, char := range word {
		if _, ok := node.children[char]; !ok {
			return false, nil
		}
		node = node.children[char]
	}
	return node.isEnd, node.command
}

func (t *CommandTrie) ShortestPrefix(word string) (string, string) {
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

var (
	Commands        []Command
	CommandsTrie    *CommandTrie
	CommandsChoice1 bool
	CommandsChoice2 bool
	CommandsChoice3 bool
)

func PrepareCommands() {
	CommandsTrie = NewTrie()

	for _, command := range Commands {
		CommandsTrie.Insert(command.Name, &command)
	}

	for _, command := range Commands {
		prefix, rest := CommandsTrie.ShortestPrefix(command.Name)
		CommandsTrie.Insert(prefix, &command)
		prefixWithRest := prefix
		for _, c := range rest {
			prefixWithRest += string(c)
			CommandsTrie.Insert(prefixWithRest, &command)
		}
	}
}
