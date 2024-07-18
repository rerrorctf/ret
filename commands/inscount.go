package commands

import (
	"embed"
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
)

//go:embed inscount.py
var embedFS embed.FS

func init() {
	Commands = append(Commands, Command{
		Name:      "inscount",
		Emoji:     "🔬",
		Func:      Inscount,
		Help:      InscountHelp,
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/inscount.go",
		Arguments: nil})
}

func InscountHelp() string {
	return fmt.Sprintf("create a pin script to count instructions from a template with ret\n")
}

func makeInscountScript(binary string) {
	scriptFile, _ := embedFS.ReadFile("inscount.py")

	script := string(scriptFile)
	script = strings.ReplaceAll(script, "%s", binary)

	err := os.WriteFile(config.InscountPythonScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.Chmod(config.InscountPythonScriptName, 0744)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🔬 "+theme.ColorGray+"ready to count instructions:"+theme.ColorReset+" $ ./%s\n", config.InscountPythonScriptName)
}

func Inscount(args []string) {
	binaries := util.GuessBinary()

	if len(binaries) > 1 {
		fmt.Printf("⚠️ multiple candidate binaries found\n")
		for _, binary := range binaries {
			fmt.Printf("%s\n", binary)
		}
	}

	binary := binaries[0]

	if strings.Compare(binary, config.DefaultBinaryName) != 0 {
		if !util.BinaryIsExecutable(binary) {
			fmt.Printf("⚠️ "+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+" is not executable"+theme.ColorReset+"\n", binary)
		}
	}

	_, err := os.Stat(config.InscountPythonScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.InscountPythonScriptName)
	}

	makeInscountScript(binary)
}
