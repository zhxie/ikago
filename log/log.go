package log

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var allowVerbose bool
var outLogger *logger
var errLogger *logger

type logger struct {
	lock sync.Mutex
	out  io.Writer
}

func (l *logger) output(s string) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	_, err := l.out.Write([]byte(s))

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

// Verbosef prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Printf.
func Verbosef(format string, v ...interface{}) {
	if allowVerbose {
		outLogger.output(fmt.Sprintf(format, v...))
	}
}

// Verbose prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Print.
func Verbose(v ...interface{}) {
	if allowVerbose {
		outLogger.output(fmt.Sprint(v...))
	}
}

// Verboseln prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Println.
func Verboseln(v ...interface{}) {
	if allowVerbose {
		outLogger.output(fmt.Sprintln(v...))
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
