package commands

import (
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/theme"
	"time"
)

func vpsHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "vps" + theme.ColorGray + " [create/list/destroy]" + theme.ColorReset + "\n")
	fmt.Printf("  ☁️  create and manage google cloud compute instances with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/vps.go" + theme.ColorReset + "\n")
}

func createVps() string {
	instanceName := fmt.Sprintf("ret-vps-instance-%v", time.Now().UTC().Format("20060102150405"))

	project := config.GoogleCloudProject

	region := config.GoogleCloudRegion

	image := "projects/ubuntu-os-cloud/global/images/ubuntu-minimal-2404-noble-amd64-v20240608"

	args := []string{
		"compute", "instances", "create", instanceName,
		fmt.Sprintf("--project=%s", project),
		fmt.Sprintf("--zone=%s", region),
		"--machine-type=e2-micro",
		"--network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default",
		"--maintenance-policy=MIGRATE",
		"--provisioning-model=STANDARD",
		"--no-service-account",
		"--no-scopes",
		fmt.Sprintf("--create-disk=auto-delete=yes,boot=yes,device-name=%s,image=%s,mode=rw,size=10,type=projects/%s/zones/%s/diskTypes/pd-balanced",
			instanceName, image, project, region),
		"--no-shielded-secure-boot",
		"--shielded-vtpm",
		"--shielded-integrity-monitoring",
		"--labels=goog-ec-src=vm_add-gcloud",
		"--reservation-affinity=any",
		fmt.Sprintf("--metadata=ssh-keys=%s", config.GoogleCloudSSHKey),
	}
	create := exec.Command("gcloud", args...)

	create.Stdin = os.Stdin
	create.Stdout = os.Stdout
	create.Stderr = os.Stderr

	err := create.Run()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		os.Exit(1)
	}

	args = []string{
		"compute", "instances", "describe", instanceName,
		fmt.Sprintf("--project=%s", project),
		fmt.Sprintf("--zone=%s", region),
		"--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
	}

	getIp := exec.Command("gcloud", args...)

	getIpOutput, err := getIp.CombinedOutput()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		os.Exit(1)
	}

	ip := string(getIpOutput)

	return ip
}

func listVps() {
	project := config.GoogleCloudProject

	region := config.GoogleCloudRegion

	args := []string{
		"compute", "instances", "list", fmt.Sprintf("--project=%s", project),
		fmt.Sprintf("--zones=%s", region),
	}
	create := exec.Command("gcloud", args...)

	create.Stdin = os.Stdin
	create.Stdout = os.Stdout
	create.Stderr = os.Stderr

	err := create.Run()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		os.Exit(1)
	}
}

func destroyVps(instanceName string) {
	project := config.GoogleCloudProject

	region := config.GoogleCloudRegion

	args := []string{
		"compute", "instances", "delete", fmt.Sprintf("--project=%s", project),
		fmt.Sprintf("--zone=%s", region), instanceName,
	}
	create := exec.Command("gcloud", args...)

	create.Stdin = os.Stdin
	create.Stdout = os.Stdout
	create.Stderr = os.Stderr

	err := create.Run()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		os.Exit(1)
	}
}

func validateConfig() bool {
	if config.GoogleCloudProject == "" {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no google cloud project found in %s\n", config.UserConfig)
		return false
	}
	if config.GoogleCloudRegion == "" {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no google cloud region found in %s\n", config.UserConfig)
		return false
	}
	return true
}

func Vps(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			vpsHelp()
			os.Exit(1)
		case "create", "list", "destroy":
			if !validateConfig() {
				os.Exit(1)
			}
			switch args[0] {
			case "create":
				createVps()
			case "list":
				listVps()
			case "destroy":
				if len(args) < 2 {
					fmt.Printf("💥 " + theme.ColorRed + " error" + theme.ColorReset + ": missing instance name for destroy\n")
					os.Exit(1)
				}
				destroyVps(args[1])
			}
			return
		default:
			vpsHelp()
			os.Exit(1)
		}
	} else {
		vpsHelp()
		os.Exit(1)
	}
}
