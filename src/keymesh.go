package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// error checker
func check(e error) {
	if e != nil {
		panic(e)
	}
}

var help_msg string = `
store contents of key.pub in remote .ssh/authorized_keys

usage:

arguments:
-u    user name
-s    supress stdout
-k    specify key path
-p    ssh port
-m    multiple hosts: -m "host1 host2 host3"
-f    read hosts from file separated by new line
-t    command timeout in seconds (default is 120)
-l    logfile name (default is keymesh.log)
-o    execute in order instead of asynchronously
`

// init some vars
var (
	key    string
	uname  string
	target string
	hosts  []string
)

// i bet theres a module for this but meh. taks in the string or error
// and the logfile name. returns an error or nil
func logit(msg interface{}, logfile string) error {
	// open our file, you can modify permissions here, currently 666
	file, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("logit encountered an error...", file, ":", err)
		return nil
	}
	// wait to close the file until were done
	defer file.Close()
	// set the logfile here
	log.SetOutput(file)
	// determine if its a str or err type
	switch v := msg.(type) {
	case string:
		fmt.Sprintf("%v", v)
		// i believe we had to use pointers here due the interface{}
		// type...cant remember :)
		logmsg := &msg
		log.Println(*logmsg)
	case error:
		fmt.Sprintf("%v", v)
		logmsg := &msg
		log.Println(*logmsg)
	default:
		// otherwise we got an unexpected type
		fmt.Sprintf("%v", v)
		err := errors.New("received bad type, expected string or error")
		return err

	}
	return nil
}

// if -f is supplied this is where we parse that file. currently has
// very basic file support, entries separted by newline. like yaml or
// json options. xml can go to hell
func readFile(path string) []string {
	// open it
	file, err := os.Open(path)
	check(err)
	// wait to close it
	defer file.Close()
	// init an array
	var lines []string
	// create instance of a scanner
	scanner := bufio.NewScanner(file)
	// iter the file
	for scanner.Scan() {
		// we dont like blank lines, skip them
		if scanner.Text() == "" {
			continue
		}
		// append the winners to the lines list
		lines = append(lines, scanner.Text())
	}
	return lines
}

// read in the key and return it in the correct format
func publicKey(path string) []byte {
	k, e := ioutil.ReadFile(path)
	check(e)
	if k[len(k)-1] == 10 {
		k = k[:len(k)-1]
	}
	// key, err := ssh.ParsePrivateKey(k)
	// check(err)
	return k
}

// this is where the command is sent. takes in the command being sent,
// the remote machine and a port, as well as our arg map....and then of
// the ssh key. returns the stdout as str
func executeCmd(cmd, host, port string, args map[string]string, conf *ssh.ClientConfig) string {
	// init our stdout
	var stdout bytes.Buffer
	// log the attempt
	info := fmt.Sprintf("attempting to connect to %v on port %v as %v\n", host, port, conf.User)
	logit(info, args["logfile"])
	// dial the host
	conn, conn_err := ssh.Dial("tcp", fmt.Sprintf("%s:%v", host, port), conf)
	if conn_err != nil {
		// here we manually handle the err instead of passing it to
		// check(). we want to know why and log it
		fmt.Printf("got a connection error (dial) in executeCmd!\n")
		conn_err_msg := fmt.Sprintf("error connecting to %v on port %v as %v\n", host, port, conf.User)
		logit(conn_err_msg, args["logfile"])
		return conn_err_msg
	}
	// create the ssh session
	session, session_err := conn.NewSession()
	if session_err != nil {
		// again, we manually handle the err
		fmt.Printf("got a session error in executeCmd!\n")
		ses_err_msg := fmt.Sprintf("error connecting to %v on port %v as %v\n", host, port, conf.User)
		logit(ses_err_msg, args["logfile"])
		return ses_err_msg
	}
	// wait to close
	defer session.Close()
	// get the stdout
	session.Stdout = &stdout
	//logit
	logit(fmt.Sprintf("running %v on %v\n", cmd, host), args["logfile"])
	// run the command
	session.Run(cmd)
	// pass the stdout back to our channel
	return fmt.Sprintf("%s:\n%s", host, stdout.String())

}

// techEcho() - turns terminal echo on or off.
func termEcho(on bool) {
	// Common settings and variables for both stty calls.
	attrs := syscall.ProcAttr{
		Dir:   "",
		Env:   []string{},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys:   nil}
	var ws syscall.WaitStatus
	cmd := "echo"
	if on == false {
		cmd = "-echo"
	}

	// Enable/disable echoing.
	pid, err := syscall.ForkExec(
		"/bin/stty",
		[]string{"stty", cmd},
		&attrs)
	if err != nil {
		panic(err)
	}

	// Wait for the stty process to complete.
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		panic(err)
	}
}

// getPassword - Prompt for password.
func getPassword(prompt string) string {
	fmt.Print(prompt)

	// Catch a ^C interrupt.
	// Make sure that we reset term echo before exiting.
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		for _ = range signalChannel {
			fmt.Println("\n^C interrupt.")
			termEcho(true)
			os.Exit(1)
		}
	}()

	// Echo is disabled, now grab the data.
	termEcho(false) // disable terminal echo
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	termEcho(true) // always re-enable terminal echo
	fmt.Println("")
	if err != nil {
		// The terminal has been reset, go ahead and exit.
		fmt.Println("ERROR:", err.Error())
		os.Exit(1)
	}
	return strings.TrimSpace(text)
}

func main() {
	// not pleased with the flags package, just going to parse args
	raw_args := os.Args
	// the args will be accessed from a map
	args := make(map[string]string)
	// we want the command first and host second
	if len(raw_args) > 2 {
		args["cmd"] = raw_args[1]
		args["host"] = raw_args[2]
	} else if len(raw_args) == 1 {
		fmt.Println(help_msg)
		fmt.Printf("expected two args, got %v\n", len(raw_args)-1)
		os.Exit(1)
	}
	// define our defaults
	args["silent"] = "false"
	args["multi"] = "false"
	args["uname"] = "none"
	args["key"] = "default"
	args["port"] = "22"
	args["logfile"] = "keymesh.log"
	args["timeout"] = "120"
	args["ordered"] = "false"
	args["file"] = "false"
	// parse em
	for i, a := range raw_args[1:] {
		if !strings.HasPrefix(a, "-") {
			continue
		} else if a == "-h" {
			fmt.Println(help_msg)
			os.Exit(0)
		} else if a == "-s" {
			args["silent"] = "true"
		} else if a == "-u" {
			args["uname"] = raw_args[i+2]
		} else if a == "-p" {
			args["port"] = raw_args[i+2]
		} else if a == "-k" {
			args["key"] = raw_args[i+2]
		} else if a == "-m" {
			args["multi"] = raw_args[i+2]
		} else if a == "-t" {
			args["timeout"] = raw_args[i+2]
		} else if a == "-l" {
			args["logfile"] = raw_args[i+2]
		} else if a == "-o" {
			args["ordered"] = "true"
		} else if strings.HasPrefix(a, "--") {
			continue
		} else if a == "-f" {
			args["file"] = raw_args[i+2]
		} else {
			fmt.Println(help_msg)
			fmt.Printf("unexpected argument: %v\n", a)
			os.Exit(1)
		}
	}

	// get the default user
	usr, err := user.Current()
	check(err)

	// weve technically already parsed the args but weve got more work
	// to do
	// in windows getting the uname is not straight forward (duh),
	// looks like it usually returns PCNAME\USER
	if args["uname"] == "none" {
		if strings.Contains(usr.Username, "\\") {
			args["uname"] = strings.Split(usr.Username, "\\")[1]
		} else {
			// were on a nice cozy posix system
			args["uname"] = usr.Username
		}
	}
	// now figure out how many hosts there are, if multi isnt false,
	// then multiple hosts were specified
	if args["multi"] != "false" {
		// in which case we want to break them up into fields, which
		// gives us our hosts array
		hosts = strings.Fields(args["multi"])
	} else if args["multi"] == "false" && args["file"] == "false" {
		// otherwise only one host was supplied, append it to our
		// hosts array from above (to simplify the iteration)
		hosts = append(hosts, args["host"])
	} else if args["file"] != "false" {
		// otherwise we gotta file supplied
		hosts = readFile(args["file"])
	} else {
		// otherwise some condition i couldnt forsee happened
		fmt.Println("couldnt determine the host(s)")
		//--TODO: ADD LOG LINE HERE
	}
	// here we determine the key path. this is where youd change the
	// default key location if needed
	if args["key"] == "default" {
		k := usr.HomeDir + "/.ssh/id_rsa"
		key = filepath.FromSlash(k)
	} else {
		key = args["key"]
	}
	key := string(publicKey(args["key"]))
	// create a channel to communicate between routines
	res := make(chan string)
	// create a timeout condition; 120 seconds or user supplied
	t, time_out_conversion_err := strconv.Atoi(args["timeout"])
	if time_out_conversion_err != nil {
		fmt.Println(help_msg)
		fmt.Println("expected timeout to be a number in seconds (type int)")
		os.Exit(1)
	}
	timeout := time.After(time.Duration(t) * time.Second)

	// now we iter over that hosts array we created
	exec.Command("stty -echo")
	pass := getPassword("password: ")
	exec.Command("stty echo")
	for _, host := range hosts {
		// if a string was supplied such as admin@some-host, then they
		// are specifying a username, split the string up accordingly
		if strings.Contains(host, "@") {
			uname = strings.Split(host, "@")[0]
			target = strings.Split(host, "@")[1]
			// otherwise we're assuming the target machine is the same
			// user as this machine
		} else {
			uname = args["uname"]
			target = host
		}
		// configure our ssh client config
		conf := &ssh.ClientConfig{
			User:            uname,
			Auth:            []ssh.AuthMethod{ssh.Password(pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		command := fmt.Sprintf("echo %v >> .ssh/authorized_keys;echo >> .ssh/authorized_keys", key)
		args["cmd"] = command
		if args["ordered"] == "true" {
			res := executeCmd(args["cmd"], target, args["port"], args, conf)
			fmt.Println(res)
		} else {
			// here create an anon goroutine (async function)
			go func(target string, port string) {
				// run our exec func and pass the data back to our channel
				// from earlier
				res <- executeCmd(args["cmd"], target, args["port"], args, conf)
			}(target, args["port"]) // the goroutine needs to end with these
		}
	}
	// now everything should be running in the BG and we're listening
	// on that channel
	if args["ordered"] == "false" {
		for i := 0; i < len(hosts); i++ {
			select {
			case results := <-res:
				fmt.Sprintf("%v", results)
				fmt.Printf("\rcompleted: %v", i)
			case <-timeout:
				//--TODO log line
				alert := fmt.Sprintf("%v timed out...", hosts[i])
				logit(alert, args["logfile"])
				fmt.Println(alert)
				return
			}
		}
	}
	fmt.Printf("\ncomplete\n")
}
