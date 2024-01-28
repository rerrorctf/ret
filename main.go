package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"rctf/commands"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
)

func createDefaultConfig(configPath string) {
	var userConfig data.Config

	userConfig.GhidraInstallPath = config.GhidraInstallPath
	userConfig.GhidraProjectPath = config.GhidraProjectPath
	userConfig.PwnScriptName = config.PwnScriptName

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		fmt.Println("error opening file:", err)
		os.Exit(1)
	}
}

func parseUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, config.UserConfig)

	jsonData, err := os.ReadFile(configPath)
	if err != nil {
		createDefaultConfig(configPath)
		return
	}

	var userConfig data.Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	if len(userConfig.GhidraInstallPath) > 0 {
		config.GhidraInstallPath = userConfig.GhidraInstallPath
	}

	if len(userConfig.GhidraProjectPath) > 0 {
		config.GhidraProjectPath = userConfig.GhidraProjectPath
	}

	if len(userConfig.PwnScriptName) > 0 {
		config.PwnScriptName = userConfig.PwnScriptName
	}
}

func ensureDirectory(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Println("mkdir", dirPath)
		}
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}
}

func ensureSkeleton() {
	ensureDirectory(config.FolderName)
	ensureDirectory(config.FilesFolderName)
}

func main() {
	flag.BoolVar(&config.Verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n"+theme.ColorReset)

		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, "\n")

		fmt.Fprintln(os.Stderr, theme.ColorRed+
			`                FFFF                                                 
            FFFFFFFFFFFFF            FFF                                
      F  FFFFFFFFF   FFFFF      FFFFFFFFF                               
     FFFFFFFF         FFFFFFFFFFFFFFFF                                  
      FF       FFFFFFFFFFFF FFFFF                                       
       FF   FFFFFFFFFFF    F FFFFFFFFF                                  
        FF FFFFFFFFFFF          FFFFFFFFFFFF                            
        FFF   FFFFFFFFFFFF         FFFFFFFFF                            
         FFF         FFFFFF FFFFFFFFFFFFFF                              
          FF       FFFFFFFFF FFFFFFF        FFF                         
           FF  FFFFFFFFFFFFF FFFFF      FFFFFFF                         
            FF FFFFF          FFFFFFFFFFFFFFF                           
            FFF F              FFFFFFFFF                                
             FFF                                                        
              FF                                                        
               FF                                                       
                FF                                                      
                FFF                                                     
                 FFF                                                    
                  FF`+theme.ColorReset)

		fmt.Fprintf(os.Stderr, "\n"+theme.ColorGreen+"commands"+theme.ColorReset+":\n")
		fmt.Fprintf(os.Stderr, "  🚀 "+theme.ColorBlue+"init"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  👀 "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📥 "+theme.ColorBlue+"add"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐚 "+theme.ColorBlue+"pwn"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🦖 "+theme.ColorBlue+"ghidra"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  💃 "+theme.ColorBlue+"ida"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📡 "+theme.ColorBlue+"monitor"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  ✅ "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "\n🚩 https://github.com/rerrorctf/rctf 🚩\n")
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	parseUserConfig()

	ensureSkeleton()

	switch flag.Arg(0) {
	case "init":
		commands.Init(flag.Args()[1:])
	case "add":
		commands.Add(flag.Args()[1:])
	case "status":
		commands.Status(flag.Args()[1:])
	case "pwn":
		commands.Pwn(flag.Args()[1:])
	case "ghidra":
		commands.Ghidra(flag.Args()[1:])
	case "ida":
		commands.Ida(flag.Args()[1:])
	case "monitor":
		commands.Monitor(flag.Args()[1:])
	case "check":
		commands.Check(flag.Args()[1:])
	default:
		flag.Usage()
		os.Exit(1)
	}
}
