package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

const warnLogFileSize int64 = 200 * 1024 * 1024

var (
	allowVerbose bool
)

var (
	outLogger *logger
	errLogger *logger
	logLogger *log.Logger
)

type logger struct {
	lock sync.Mutex
	out  io.Writer
}

func (l *logger) output(s string) error {
	l.lock.Lock()
	_, err := l.out.Write([]byte(s))
	l.lock.Unlock()

	if logLogger != nil {
		logLogger.Output(2, s)
	}

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
	if path != "" {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 755)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}

		stat, err := file.Stat()
		if err != nil {
			return fmt.Errorf("stat: %w", err)
		}

		if stat.Size() > warnLogFileSize {
			Infof("The log file is too large. You may delete %s manually to save disk space.\n", path)
		}

		logLogger = log.New(file, "", log.LstdFlags)
	}

	return nil
}

// Verbosef prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Printf.
func Verbosef(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if !allowVerbose && logLogger != nil {
		logLogger.Output(2, s)
	}
}

// Verbose prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Print.
func Verbose(v ...interface{}) {
	s := fmt.Sprint(v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if !allowVerbose && logLogger != nil {
		logLogger.Output(2, s)
	}
}

// Verboseln prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Println.
func Verboseln(v ...interface{}) {
	s := fmt.Sprintln(v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if !allowVerbose && logLogger != nil {
		logLogger.Output(2, s)
	}
}

// Infof prints message to the stdout. Arguments are handled in the manner of fmt.Printf.
func Infof(format string, v ...interface{}) {
	outLogger.output(fmt.Sprintf(format, v...))
}

// Info prints message to the stdout. Arguments are handled in the manner of fmt.Print.
func Info(v ...interface{}) {
	outLogger.output(fmt.Sprint(v...))
}

// Infoln prints message to the stdout. Arguments are handled in the manner of fmt.Println.
func Infoln(v ...interface{}) {
	outLogger.output(fmt.Sprintln(v...))
}

// Errorf prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorf(format string, v ...interface{}) {
	errLogger.output(fmt.Sprintf(format, v...))
}

// Error prints message to the stderr. Arguments are handled in the manner of fmt.Print.
func Error(v ...interface{}) {
	errLogger.output(fmt.Sprint(v...))
}

// Errorln prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorln(v ...interface{}) {
	errLogger.output(fmt.Sprintln(v...))
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
