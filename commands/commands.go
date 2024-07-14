package commands

import (
	"ret/util"
)

type CommandFunc func([]string)
type CommandHelpFunc func()

type Argument struct {
	Name     string
	Optional bool
	List     bool
}

type Command struct {
	Name      string
	Emoji     string
	Func      CommandFunc
	Help      CommandHelpFunc
	Url       string
	Arguments []Argument
}

var (
	Commands     []Command
	CommandsTrie *util.Trie
)

func PrepareCommands() {
	CommandsTrie = util.NewTrie()

	for _, command := range Commands {
		CommandsTrie.Insert(command.Name)
	}
}
