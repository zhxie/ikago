package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	allowVerbose bool
	logPath      string
)

var (
	outLogger *logger
	errLogger *logger
	logFile   *os.File
)

type logger struct {
	lock sync.Mutex
	out  io.Writer
}

func (l *logger) output(s string) error {
	l.lock.Lock()
	_, err := l.out.Write([]byte(s))
	l.lock.Unlock()

	return err
}

func init() {
	allowVerbose = false
	outLogger = &logger{out: os.Stdout}
	errLogger = &logger{out: os.Stderr}
}

// SetVerbose sets the state if verbose message is allowed to print.
func SetVerbose(allow bool) {
	allowVerbose = allow
}

// SetLog sets the path of log file.
func SetLog(path string) error {
	logPath = path

	if logFile != nil {
		err := logFile.Close()
		if err != nil {
			return fmt.Errorf("close: %w", err)
		}
	}

	if logPath != "" {
		var err error

		logFile, err = os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 755)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
	}

	return nil
}

// Close closes the logger.
func Close() error {
	if logFile != nil {
		return logFile.Close()
	}

	return nil
}

// Verbosef prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Printf.
func Verbosef(format string, v ...interface{}) {
	Verbose(fmt.Sprintf(format, v...))
}

// Verbose prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Print.
func Verbose(v ...interface{}) {
	if allowVerbose || (logFile != nil) {
		s := fmt.Sprint(v...)

		if allowVerbose {
			outLogger.output(s)
		}

		if logFile != nil {
			log(s)
		}
	}
}

// Verboseln prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Println.
func Verboseln(v ...interface{}) {
	Verbose(fmt.Sprintln(v...))
}

// Infof prints message to the stdout. Arguments are handled in the manner of fmt.Printf.
func Infof(format string, v ...interface{}) {
	Info(fmt.Sprintf(format, v...))
}

// Info prints message to the stdout. Arguments are handled in the manner of fmt.Print.
func Info(v ...interface{}) {
	s := fmt.Sprint(v...)

	outLogger.output(s)

	if logFile != nil {
		log(s)
	}
}

// Infoln prints message to the stdout. Arguments are handled in the manner of fmt.Println.
func Infoln(v ...interface{}) {
	Info(fmt.Sprintln(v...))
}

// Errorf prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorf(format string, v ...interface{}) {
	Error(fmt.Sprintf(format, v...))
}

// Error prints message to the stderr. Arguments are handled in the manner of fmt.Print.
func Error(v ...interface{}) {
	s := fmt.Sprint(v...)

	errLogger.output(s)

	if logFile != nil {
		log(s)
	}
}

// Errorln prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorln(v ...interface{}) {
	Error(fmt.Sprintln(v...))
}

// Fatalf prints message to the stderr, and ends with os.Exit(1). Arguments are handled in the manner of fmt.Printf.
func Fatalf(format string, v ...interface{}) {
	Errorf(format, v...)
	os.Exit(1)
}

// Fatal prints message to the stderr, and ends with os.Exit(1). Arguments are handled in the manner of fmt.Print.
func Fatal(v ...interface{}) {
	Error(v...)
	os.Exit(1)
}

// Fatalln prints message to the stderr, and ends with os.Exit(1). Arguments are handled in the manner of fmt.Println.
func Fatalln(v ...interface{}) {
	Errorln(v...)
	os.Exit(1)
}

func log(s string) error {
	if logFile != nil {
		t := time.Now()
		_, err := logFile.WriteString(fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d] %s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), s))
		if err != nil {
			return fmt.Errorf("log: %w", err)
		}
	}

	return nil
}
