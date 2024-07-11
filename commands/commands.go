package commands

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
	Commands []Command
)
