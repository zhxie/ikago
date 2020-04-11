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
)

var (
	outLogger *logger
	errLogger *logger
	logLogger *logger
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

func (l *logger) outputWithTime(s string) error {
	t := time.Now()
	return l.output(fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d] %s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), s))
}

func init() {
	allowVerbose = false
	outLogger = &logger{out: os.Stdout}
	errLogger = &logger{out: os.Stderr}
}

// Close closes the logger.
func Close() error {
	if logLogger != nil {
		return logLogger.out.(*os.File).Close()
	}

	return nil
}

// SetVerbose sets the state if verbose message is allowed to print.
func SetVerbose(allow bool) {
	allowVerbose = allow
}

// SetLog sets the path of log file.
func SetLog(path string) error {
	if logLogger != nil {
		err := logLogger.out.(*os.File).Close()
		if err != nil {
			return fmt.Errorf("close: %w", err)
		}
	}

	if path != "" {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 755)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		logLogger = &logger{out: file}
	}

	return nil
}

// Verbosef prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Printf.
func Verbosef(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Verbose prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Print.
func Verbose(v ...interface{}) {
	s := fmt.Sprint(v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Verboseln prints message to the stdout if verbose message is allowed to print. Arguments are handled in the manner of fmt.Println.
func Verboseln(v ...interface{}) {
	s := fmt.Sprintln(v...)

	if allowVerbose {
		outLogger.output(s)
	}
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Infof prints message to the stdout. Arguments are handled in the manner of fmt.Printf.
func Infof(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)

	outLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Info prints message to the stdout. Arguments are handled in the manner of fmt.Print.
func Info(v ...interface{}) {
	s := fmt.Sprint(v...)

	outLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Infoln prints message to the stdout. Arguments are handled in the manner of fmt.Println.
func Infoln(v ...interface{}) {
	s := fmt.Sprintln(v...)

	outLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Errorf prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)

	errLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Error prints message to the stderr. Arguments are handled in the manner of fmt.Print.
func Error(v ...interface{}) {
	s := fmt.Sprint(v...)

	errLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
}

// Errorln prints message to the stderr. Arguments are handled in the manner of fmt.Printf.
func Errorln(v ...interface{}) {
	s := fmt.Sprintln(v...)

	errLogger.output(s)
	if logLogger != nil {
		logLogger.outputWithTime(s)
	}
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
