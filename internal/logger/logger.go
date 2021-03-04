//Package logger provides a refference to the central logger and associated functions/methods
package logger

import (
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// InitDetailedLogger initializes the logrus logger with "detailed" settings
func InitDetailedLogger(f *os.File) {

	log.SetReportCaller(true)
	log.SetLevel(logrus.DebugLevel)

	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "",
		PrettyPrint:     true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			s := strings.Split(f.Function, ".")
			funcname := s[len(s)-1]
			_, filename := path.Split(f.File)
			return funcname, filename
		},
	})

	// Set output of logs to Stdout
	// Change to f for redirecting to file
	log.SetOutput(os.Stdout)

}
