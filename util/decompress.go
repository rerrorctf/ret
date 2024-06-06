package util

import (
	"fmt"
	"os"
	"os/exec"
	"ret/theme"
	"strings"
)

const (
	GZIP string = "gz"
	ZIP  string = "zip"
	XZ   string = "xz"
	VIIZ string = "7z"
	TAR  string = "tar"
)

var magics = map[string][]byte{
	GZIP: {0x1F, 0x8b},
	ZIP:  {0x50, 0x4B, 0x03, 0x04},
	XZ:   {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00},
	VIIZ: {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
	TAR:  {0x75, 0x73, 0x74, 0x61, 0x72},
}

var validExtensions = map[string][]string{
	GZIP: {"gzip", "gz"},
	ZIP:  {"zip"},
	XZ:   {"xz"},
	VIIZ: {"7z"},
	TAR:  {"tar"},
}

func IsDecompressable(path string) (string, bool) {
	splits := strings.Split(path, ".")
	if len(splits) < 2 {
		return "", false
	}

	extension := splits[len(splits)-1]

	fileType := ""
	for fType, exts := range validExtensions {
		for _, ext := range exts {
			if extension == ext {
				fileType = fType
			}
		}
	}

	// note: we test for extension validity to avoid decompressing things like APKs and epubs
	if fileType == "" {
		return "", false
	}

	buffer, err := os.ReadFile(path)
	if err != nil {
		// TODO: handle error?
		return "", false
	}

	magic := magics[fileType]

	if fileType == TAR {
		if len(buffer) < (0x101 + len(magic)) {
			return "", false
		}
		for i, b := range magic {
			// tar magic starts in the middle of the file
			if buffer[i+0x101] != b {
				return "", false
			}
		}
	} else {
		if len(buffer) < len(magic) {
			return "", false
		}
		for i, b := range magic {
			if buffer[i] != b {
				return "", false
			}
		}
	}

	return fileType, true
}

func decompressFileZip(path string) {
	unzip := exec.Command("unzip", path)

	unzipOutput, err := unzip.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", unzipOutput)
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		return
	}
}

func decompressFile7z(path string) {
	sevenZipX := exec.Command("7z", "x", path)

	sevenZipXOutput, err := sevenZipX.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", sevenZipXOutput)
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		return
	}
}

func decompressFileTar(path string) {
	tarXF := exec.Command("tar", "xf", path)

	tarXFOutput, err := tarXF.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", tarXFOutput)
		fmt.Printf("💥 "+theme.ColorRed+"error: "+theme.ColorReset+"%v\n", err)
		return
	}
}

func DecompressFile(path string) bool {
	fileType, decompressable := IsDecompressable(path)
	if !decompressable {
		return false
	}

	switch fileType {
	case GZIP:
		decompressFileTar(path)
	case ZIP:
		decompressFileZip(path)
	case XZ:
		decompressFileTar(path)
	case VIIZ:
		decompressFile7z(path)
	case TAR:
		decompressFileTar(path)
	}

	return true
}
