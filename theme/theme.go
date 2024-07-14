package theme

import "strings"

const (
	ColorReset     = "\033[0m"
	ColorRed       = "\033[31m"
	ColorGreen     = "\033[32m"
	ColorYellow    = "\033[33m"
	ColorBlue      = "\033[34m"
	ColorPurple    = "\033[35m"
	ColorCyan      = "\033[36m"
	ColorGray      = "\033[90m"
	StartUnderline = "\033[4m"
	StopUnderline  = "\033[24m"
)

func RemoveColors(message string) string {
	message = strings.ReplaceAll(message, ColorReset, "")
	message = strings.ReplaceAll(message, ColorRed, "")
	message = strings.ReplaceAll(message, ColorGreen, "")
	message = strings.ReplaceAll(message, ColorYellow, "")
	message = strings.ReplaceAll(message, ColorBlue, "")
	message = strings.ReplaceAll(message, ColorPurple, "")
	message = strings.ReplaceAll(message, ColorCyan, "")
	message = strings.ReplaceAll(message, ColorGray, "")
	message = strings.ReplaceAll(message, StartUnderline, "")
	message = strings.ReplaceAll(message, StopUnderline, "")
	return message
}
