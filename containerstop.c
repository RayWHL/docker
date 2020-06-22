// Container holds the structure defining a container object.
type Container struct {
	StreamConfig *stream.Config
	// embed for Container to support states directly.
	*State          `json:"State"`          // Needed for Engine API version <= 1.11
	Root            string                  `json:"-"` // Path to the "home" of the container, including metadata.
	BaseFS          containerfs.ContainerFS `json:"-"` // interface containing graphdriver mount
	RWLayer         layer.RWLayer           `json:"-"`
	ID              string
	Created         time.Time
	Managed         bool
	Path            string
	Args            []string
	Config          *containertypes.Config
	ImageID         image.ID `json:"Image"`
	NetworkSettings *network.Settings
	LogPath         string
	Name            string
	Driver          string
	OS              string
	// MountLabel contains the options for the 'mount' command
	MountLabel             string
	ProcessLabel           string
	RestartCount           int
	HasBeenStartedBefore   bool
	HasBeenManuallyStopped bool // used for unless-stopped restart policy
	MountPoints            map[string]*volumemounts.MountPoint
	HostConfig             *containertypes.HostConfig `json:"-"` // do not serialize the host config in the json, otherwise we'll make the container unportable
	ExecCommands           *exec.Store                `json:"-"`
	DependencyStore        agentexec.DependencyGetter `json:"-"`
	SecretReferences       []*swarmtypes.SecretReference
	ConfigReferences       []*swarmtypes.ConfigReference
	// logDriver for closing
	LogDriver      logger.Logger  `json:"-"`
	LogCopier      *logger.Copier `json:"-"`
	restartManager restartmanager.RestartManager
	attachContext  *attachContext

	// Fields here are specific to Unix platforms
	AppArmorProfile string
	HostnamePath    string
	HostsPath       string
	ShmPath         string
	ResolvConfPath  string
	SeccompProfile  string
	NoNewPrivileges bool

	// Fields here are specific to Windows
	NetworkSharedContainerID string            `json:"-"`
	SharedEndpointList       []string          `json:"-"`
	LocalLogCacheMeta        localLogCacheMeta `json:",omitempty"`
}

type services struct {
	contentStore         content.Store
	imageStore           images.Store
	containerStore       containers.Store
	namespaceStore       namespaces.Store
	snapshotters         map[string]snapshots.Snapshotter
	taskService          tasks.TasksClient
	diffService          DiffService
	eventService         EventService
	leasesService        leases.Manager
	introspectionService introspection.Service
}

// Client is the client to interact with containerd and its various services
// using a uniform interface
type Client struct {
	services
	connMu    sync.Mutex
	conn      *grpc.ClientConn
	runtime   string
	defaultns string
	platform  platforms.MatchComparer
	connector func() (*grpc.ClientConn, error)
}

// containerStop sends a stop signal, waits, sends a kill signal.
func (daemon *Daemon) containerStop(container *containerpkg.Container, seconds int) error {
	if !container.IsRunning() {
		return nil
	}

	stopSignal := container.StopSignal()
	// 1. Send a stop signal
	if err := daemon.killPossiblyDeadProcess(container, stopSignal); err != nil {
		// While normally we might "return err" here we're not going to
		// because if we can't stop the container by this point then
		// it's probably because it's already stopped. Meaning, between
		// the time of the IsRunning() call above and now it stopped.
		// Also, since the err return will be environment specific we can't
		// look for any particular (common) error that would indicate
		// that the process is already dead vs something else going wrong.
		// So, instead we'll give it up to 2 more seconds to complete and if
		// by that time the container is still running, then the error
		// we got is probably valid and so we force kill it.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if status := <-container.Wait(ctx, containerpkg.WaitConditionNotRunning); status.Err() != nil {
			logrus.Infof("Container failed to stop after sending signal %d to the process, force killing", stopSignal)
			if err := daemon.killPossiblyDeadProcess(container, 9); err != nil {
				return err
			}
		}
	}

	// 2. Wait for the process to exit on its own
	ctx := context.Background()
	if seconds >= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
		defer cancel()
	}

	if status := <-container.Wait(ctx, containerpkg.WaitConditionNotRunning); status.Err() != nil {
		logrus.Infof("Container %v failed to exit within %d seconds of signal %d - using the force", container.ID, seconds, stopSignal)
		// 3. If it doesn't, then send SIGKILL
		//到这了
		if err := daemon.Kill(container); err != nil {
			// Wait without a timeout, ignore result.
			<-container.Wait(context.Background(), containerpkg.WaitConditionNotRunning)
			logrus.Warn(err) // Don't return error because we only care that container is stopped, not what function stopped it
		}
	}

	//wait等等容器stop，此处在所有操作完成后执行
	daemon.LogContainerEvent(container, "stop")
	return nil
}


// killPossibleDeadProcess is a wrapper around killSig() suppressing "no such process" error.
func (daemon *Daemon) killPossiblyDeadProcess(container *containerpkg.Container, sig int) error {
	err := daemon.killWithSignal(container, sig)
	if errdefs.IsNotFound(err) {
		e := errNoSuchProcess{container.GetPID(), sig}
		logrus.Debug(e)
		return e
	}
	return err
}


// killWithSignal sends the container the given signal. This wrapper for the
// host specific kill command prepares the container before attempting
// to send the signal. An error is returned if the container is paused
// or not running, or if there is a problem returned from the
// underlying kill command.
func (daemon *Daemon) killWithSignal(container *containerpkg.Container, sig int) error {
	logrus.Debugf("Sending kill signal %d to container %s", sig, container.ID)
	container.Lock()
	defer container.Unlock()

	if !container.Running {
		return errNotRunning(container.ID)
	}

	var unpause bool
	if container.Config.StopSignal != "" && syscall.Signal(sig) != syscall.SIGKILL {
		containerStopSignal, err := signal.ParseSignal(container.Config.StopSignal)
		if err != nil {
			return err
		}
		if containerStopSignal == syscall.Signal(sig) {
			container.ExitOnNext()
			unpause = container.Paused
		}
	} else {
		container.ExitOnNext()
		unpause = container.Paused
	}

	if !daemon.IsShuttingDown() {
		container.HasBeenManuallyStopped = true
		container.CheckpointTo(daemon.containersReplica)
	}

	// if the container is currently restarting we do not need to send the signal
	// to the process. Telling the monitor that it should exit on its next event
	// loop is enough
	if container.Restarting {
		return nil
	}

	if err := daemon.kill(container, sig); err != nil {
		if errdefs.IsNotFound(err) {
			unpause = false
			logrus.WithError(err).WithField("container", container.ID).WithField("action", "kill").Debug("container kill failed because of 'container not found' or 'no such process'")
		} else {
			return errors.Wrapf(err, "Cannot kill container %s", container.ID)
		}
	}

	if unpause {
		// above kill signal will be sent once resume is finished
		if err := daemon.containerd.Resume(context.Background(), container.ID); err != nil {
			logrus.Warnf("Cannot unpause container %s: %s", container.ID, err)
		}
	}

	attributes := map[string]string{
		"signal": fmt.Sprintf("%d", sig),
	}
	daemon.LogContainerEventWithAttributes(container, "kill", attributes)
	return nil
}


func (daemon *Daemon) kill(c *containerpkg.Container, sig int) error {
	return daemon.containerd.SignalProcess(context.Background(), c.ID, libcontainerdtypes.InitProcessName, sig)
}

func (c *client) SignalProcess(ctx context.Context, containerID, processID string, signal int) error {
	p, err := c.getProcess(ctx, containerID, processID)
	if err != nil {
		return err
	}
	return wrapError(p.Kill(ctx, syscall.Signal(signal)))
}
//p.Kill  Task接口的kill函数，包括以及dockerd中
/**
 * type task struct {
	client *Client

	io  cio.IO
	id  string
	pid uint32
}
**/
func (t *task) Kill(ctx context.Context, s syscall.Signal, opts ...KillOpts) error {
	
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": vendor task Kill: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
	file.Close()
	
	var i KillInfo
	for _, o := range opts {
		if err := o(ctx, &i); err != nil {
			return err
		}
	}
	_, err := t.client.TaskService().Kill(ctx, &tasks.KillRequest{
		Signal:      uint32(s),
		ContainerID: t.id,
		ExecID:      i.ExecID,
		All:         i.All,
	})
	if err != nil {
		return errdefs.FromGRPC(err)
	}
	return nil
}
type tasksClient struct {
	cc *grpc.ClientConn
}
func (c *tasksClient) Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*types1.Empty, error) {
	out := new(types1.Empty)
	err := c.cc.Invoke(ctx, "/containerd.services.tasks.v1.Tasks/Kill", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
// Invoke sends the RPC request on the wire and returns after response is
// received.  This is typically called by generated code.
//
// All errors returned by Invoke are compatible with the status package.
func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...CallOption) error {
	// allow interceptor to see all applicable call options, which means those
	// configured as defaults from dial option as well as per-call options
	opts = combine(cc.dopts.callOptions, opts)

	if cc.dopts.unaryInt != nil {
		return cc.dopts.unaryInt(ctx, method, args, reply, cc, invoke, opts...)
	}
	return invoke(ctx, method, args, reply, cc, opts...)
}

var unaryStreamDesc = &StreamDesc{ServerStreams: false, ClientStreams: false}

func invoke(ctx context.Context, method string, req, reply interface{}, cc *ClientConn, opts ...CallOption) error {
	cs, err := newClientStream(ctx, unaryStreamDesc, cc, method, opts...)
	if err != nil {
		return err
	}
	if err := cs.SendMsg(req); err != nil {
		return err
	}
	return cs.RecvMsg(reply)
}

// TaskService returns the underlying TasksClient
func (c *Client) TaskService() tasks.TasksClient {
	if c.taskService != nil {
		return c.taskService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return tasks.NewTasksClient(c.conn)
}

func (c *client) getProcess(ctx context.Context, containerID, processID string) (containerd.Process, error) {
	ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}
	t, err := ctr.Task(ctx, nil)
	if err != nil {
		if containerderrors.IsNotFound(err) {
			return nil, errors.WithStack(errdefs.NotFound(errors.New("container is not running")))
		}
		return nil, wrapError(err)
	}
	if processID == libcontainerdtypes.InitProcessName {
		//此处返回
		return t, nil
	}
	p, err := t.LoadProcess(ctx, processID, nil)
	if err != nil {
		if containerderrors.IsNotFound(err) {
			return nil, errors.WithStack(errdefs.NotFound(errors.New("no such exec")))
		}
		return nil, wrapError(err)
	}
	return p, nil
}


func (c *client) getContainer(ctx context.Context, id string) (containerd.Container, error) {
	ctr, err := c.client.LoadContainer(ctx, id)
	if err != nil {
		if containerderrors.IsNotFound(err) {
			return nil, errors.WithStack(errdefs.NotFound(errors.New("no such container")))
		}
		return nil, wrapError(err)
	}
	return ctr, nil
}

func (c *container) Task(ctx context.Context, attach cio.Attach) (Task, error) {
	return c.loadTask(ctx, attach)
}

func (c *container) loadTask(ctx context.Context, ioAttach cio.Attach) (Task, error) {
	response, err := c.client.TaskService().Get(ctx, &tasks.GetRequest{
		ContainerID: c.id,
	})
	if err != nil {
		err = errdefs.FromGRPC(err)
		if errdefs.IsNotFound(err) {
			return nil, errors.Wrapf(err, "no running task found")
		}
		return nil, err
	}
	var i cio.IO
	if ioAttach != nil && response.Process.Status != tasktypes.StatusUnknown {
		// Do not attach IO for task in unknown state, because there
		// are no fifo paths anyway.
		if i, err = attachExistingIO(response, ioAttach); err != nil {
			return nil, err
		}
	}
	t := &task{
		client: c.client,
		io:     i,
		id:     response.Process.ID,
		pid:    response.Process.Pid,
	}
	return t, nil
}
//dockerd中kill


//进入containerd源码

func (p *process) Kill(ctx context.Context, s syscall.Signal, opts ...KillOpts) error {
	var i KillInfo
	for _, o := range opts {
		if err := o(ctx, &i); err != nil {
			return err
		}
	}
	_, err := p.task.client.TaskService().Kill(ctx, &tasks.KillRequest{
		Signal:      uint32(s),
		ContainerID: p.task.id,
		ExecID:      p.id,
		All:         i.All,
	})
	return errdefs.FromGRPC(err)
}

// TaskService returns the underlying TasksClient
func (c *Client) TaskService() tasks.TasksClient {
	if c.taskService != nil {
		return c.taskService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return tasks.NewTasksClient(c.conn)
}

func (c *tasksClient) Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*types1.Empty, error) {
	out := new(types1.Empty)
	err := c.cc.Invoke(ctx, "/containerd.services.tasks.v1.Tasks/Kill", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Invoke sends the RPC request on the wire and returns after response is
// received.  This is typically called by generated code.
//
// All errors returned by Invoke are compatible with the status package.
func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...CallOption) error {
	// allow interceptor to see all applicable call options, which means those
	// configured as defaults from dial option as well as per-call options
	opts = combine(cc.dopts.callOptions, opts)

	if cc.dopts.unaryInt != nil {
		return cc.dopts.unaryInt(ctx, method, args, reply, cc, invoke, opts...)
	}
	return invoke(ctx, method, args, reply, cc, opts...)
}

func invoke(ctx context.Context, method string, req, reply interface{}, cc *ClientConn, opts ...CallOption) error {
	cs, err := newClientStream(ctx, unaryStreamDesc, cc, method, opts...)
	if err != nil {
		return err
	}
	if err := cs.SendMsg(req); err != nil {
		return err
	}
	return cs.RecvMsg(reply)
}





/**
 * containerd
 * 处理kill请求函数
 * */
func _Tasks_Kill_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KillRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TasksServer).Kill(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/containerd.services.tasks.v1.Tasks/Kill",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TasksServer).Kill(ctx, req.(*KillRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func (s *service) Kill(ctx context.Context, r *api.KillRequest) (*ptypes.Empty, error) {
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": containerd service(tasks) Kill: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
	file.Close()
	return s.local.Kill(ctx, r)
}
// Process is a runtime object for an executing process inside a container
type Process interface {
	// ID of the process
	ID() string
	// State returns the process state
	State(context.Context) (State, error)
	// Kill signals a container
	Kill(context.Context, uint32, bool) error
	// Pty resizes the processes pty/console
	ResizePty(context.Context, ConsoleSize) error
	// CloseStdin closes the processes stdin
	CloseIO(context.Context) error
	// Start the container's user defined process
	Start(context.Context) error
	// Wait for the process to exit
	Wait(context.Context) (*Exit, error)
	// Delete deletes the process
	Delete(context.Context) (*Exit, error)
}
func (l *local) Kill(ctx context.Context, r *api.KillRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {

	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)		//类型转换... Process是一个接口
	if r.ExecID != "" {	//not here
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	if err := p.Kill(ctx, r.Signal, r.All); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// Kill the task using the provided signal
//
// Optionally send the signal to all processes that are a child of the task
func (t *Task) Kill(ctx context.Context, signal uint32, all bool) error {
	
	if _, err := t.shim.Kill(ctx, &shim.KillRequest{
		ID:     t.id,
		Signal: signal,
		All:    all,
	}); err != nil {
		return errdefs.FromGRPC(err)
	}
	return nil
}

func (c *shimClient) Kill(ctx context.Context, req *KillRequest) (*types1.Empty, error) {
	var resp types1.Empty
	if err := c.client.Call(ctx, "containerd.runtime.linux.shim.v1.Shim", "Kill", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}



//后续进入shim
"Kill": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
			var req KillRequest
			if err := unmarshal(&req); err != nil {
				return nil, err
			}
			return svc.Kill(ctx, &req)
		}

// Service is the shim implementation of a remote shim over GRPC
type Service struct {
	mu sync.Mutex

	config    Config
	context   context.Context
	processes map[string]process.Process
	events    chan interface{}
	platform  stdio.Platform
	ec        chan runc.Exit

	// Filled by Create()
	id     string
	bundle string
}

// Kill a process with the provided signal
func (s *Service) Kill(ctx context.Context, r *shimapi.KillRequest) (*ptypes.Empty, error) {

	if r.ID == "" {	//not here
		p, err := s.getInitProcess()
		if err != nil {
			return nil, err
		}
		if err := p.Kill(ctx, r.Signal, r.All); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		return empty, nil
	}

	p, err := s.getExecProcess(r.ID)
	if err != nil {
		return nil, err
	}
	if err := p.Kill(ctx, r.Signal, r.All); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

type initState interface {
	Start(context.Context) error
	Delete(context.Context) error
	Pause(context.Context) error
	Resume(context.Context) error
	Update(context.Context, *google_protobuf.Any) error
	Checkpoint(context.Context, *CheckpointConfig) error
	Exec(context.Context, string, *ExecConfig) (Process, error)
	Kill(context.Context, uint32, bool) error
	SetExited(int)
	Status(context.Context) (string, error)
}

// Kill the init process
func (p *Init) Kill(ctx context.Context, signal uint32, all bool) error {
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": Init Kill: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
	file.Close()

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Kill(ctx, signal, all)
}

type runningState struct {
	p *Init
}

func (s *runningState) Kill(ctx context.Context, sig uint32, all bool) error {
	
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": runningState Kill: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
	file.Close()

	return s.p.kill(ctx, sig, all)
}

func (p *Init) kill(ctx context.Context, signal uint32, all bool) error {
	err := p.runtime.Kill(ctx, p.id, int(signal), &runc.KillOpts{
		All: all,
	})
	return checkKillError(err)
}

// Kill sends the specified signal to the container
func (r *Runc) Kill(context context.Context, id string, sig int, opts *KillOpts) error {
	args := []string{
		"kill",
	}
	if opts != nil {
		args = append(args, opts.args()...)
	}
	return r.runOrError(r.command(context, append(args, id, strconv.Itoa(sig))...))
}

// Runc is the client to the runc cli
type Runc struct {
	//If command is empty, DefaultCommand is used
	Command       string
	Root          string
	Debug         bool
	Log           string
	LogFormat     Format
	PdeathSignal  syscall.Signal
	Setpgid       bool
	Criu          string
	SystemdCgroup bool
	Rootless      *bool // nil stands for "auto"
}


func (r *Runc) command(context context.Context, args ...string) *exec.Cmd {
	
	command := r.Command
	if command == "" {
		command = DefaultCommand
	}
	cmd := exec.CommandContext(context, command, append(r.args(), args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: r.Setpgid,
	}
	cmd.Env = filterEnv(os.Environ(), "NOTIFY_SOCKET") // NOTIFY_SOCKET introduces a special behavior in runc but should only be set if invoked from systemd
	if r.PdeathSignal != 0 {
		cmd.SysProcAttr.Pdeathsig = r.PdeathSignal
	}

	return cmd
}

//进入runc

var killCommand = cli.Command{
	Name:  "kill",
	Usage: "kill sends the specified signal (default: SIGTERM) to the container's init process",
	ArgsUsage: `<container-id> [signal]

Where "<container-id>" is the name for the instance of the container and
"[signal]" is the signal to be sent to the init process.

EXAMPLE:
For example, if the container id is "ubuntu01" the following will send a "KILL"
signal to the init process of the "ubuntu01" container:
	 
       # runc kill ubuntu01 KILL`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "send the specified signal to all processes inside the container",
		},
	},
	Action: func(context *cli.Context) error {
		var timeLayoutStr = "2006-01-02 15:04:05"
	
		filePath:="/root/containerd_log.txt"
		file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
		_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": runc Kill: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
		file.Close()

		if err := checkArgs(context, 1, minArgs); err != nil {
			return err
		}
		if err := checkArgs(context, 2, maxArgs); err != nil {
			return err
		}
		container, err := getContainer(context)
		if err != nil {
			return err
		}

		sigstr := context.Args().Get(1)
		if sigstr == "" {
			sigstr = "SIGTERM"
		}

		signal, err := parseSignal(sigstr)
		if err != nil {
			return err
		}
		return container.Signal(signal, context.Bool("all"))
	},
}

func (c *linuxContainer) Signal(s os.Signal, all bool) error {
	c.m.Lock()
	defer c.m.Unlock()
	if all {
		return signalAllProcesses(c.cgroupManager, s)
	}
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	// to avoid a PID reuse attack
	if status == Running || status == Created || status == Paused {
		//here!
		if err := c.initProcess.signal(s); err != nil {
			return newSystemErrorWithCause(err, "signaling init process")
		}
		return nil
	}
	return newGenericError(fmt.Errorf("container not running"), ContainerNotRunning)
}


func (p *nonChildProcess) signal(s os.Signal) error {
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": runc nonChildProcess signal: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "\n")
	
	file.Close()

	proc, err := os.FindProcess(p.processPid)
	if err != nil {
		return err
	}
	return proc.Signal(s)
}

//runc delete
var deleteCommand = cli.Command{
	Name:  "delete",
	Usage: "delete any resources held by the container often used with detached container",
	ArgsUsage: `<container-id>

Where "<container-id>" is the name for the instance of the container.

EXAMPLE:
For example, if the container id is "ubuntu01" and runc list currently shows the
status of "ubuntu01" as "stopped" the following will delete resources held for
"ubuntu01" removing "ubuntu01" from the runc list of containers:

       # runc delete ubuntu01`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "Forcibly deletes the container if it is still running (uses SIGKILL)",
		},
	},
	Action: func(context *cli.Context) error {
		

		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}

		id := context.Args().First()
		force := context.Bool("force")
		container, err := getContainer(context)
		if err != nil {
			if lerr, ok := err.(libcontainer.Error); ok && lerr.Code() == libcontainer.ContainerNotExists {
				// if there was an aborted start or something of the sort then the container's directory could exist but
				// libcontainer does not see it because the state.json file inside that directory was never created.
				path := filepath.Join(context.GlobalString("root"), id)
				if e := os.RemoveAll(path); e != nil {
					fmt.Fprintf(os.Stderr, "remove %s: %v\n", path, e)
				}
				if force {
					return nil
				}
			}
			return err
		}
		s, err := container.Status()
		if err != nil {
			return err
		}
		switch s {
		case libcontainer.Stopped:
			destroy(container)
		case libcontainer.Created:
			return killContainer(container)
		default:
			if force {
				return killContainer(container)
			}
			return fmt.Errorf("cannot delete container %s that is not stopped: %s\n", id, s)
		}

		return nil
	},
}

//
//dockerd路由


// ProcessEvent is called by libcontainerd whenever an event occurs
func (daemon *Daemon) ProcessEvent(id string, e libcontainerdtypes.EventType, ei libcontainerdtypes.EventInfo) error {
	c, err := daemon.GetContainer(id)
	if err != nil {
		return errors.Wrapf(err, "could not find container %s", id)
	}

	switch e {
	case libcontainerdtypes.EventOOM:
		// StateOOM is Linux specific and should never be hit on Windows
		if isWindows {
			return errors.New("received StateOOM from libcontainerd on Windows. This should never happen")
		}

		c.Lock()
		defer c.Unlock()
		daemon.updateHealthMonitor(c)
		if err := c.CheckpointTo(daemon.containersReplica); err != nil {
			return err
		}

		daemon.LogContainerEvent(c, "oom")
	case libcontainerdtypes.EventExit:
		if int(ei.Pid) == c.Pid {
			var timeLayoutStr = "2006-01-02 15:04:05"
	
			filePath:="/root/containerd_log.txt"
			file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
			_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": daemon ProcessEvent(delete): pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "tid " +strconv.Itoa(unix.Gettid())+ "\n")
	
			file.Close()

			c.Lock()
			_, _, err := daemon.containerd.DeleteTask(context.Background(), c.ID)
			if err != nil {
				logrus.WithError(err).Warnf("failed to delete container %s from containerd", c.ID)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c.StreamConfig.Wait(ctx)
			cancel()
			c.Reset(false)

			exitStatus := container.ExitStatus{
				ExitCode:  int(ei.ExitCode),
				ExitedAt:  ei.ExitedAt,
				OOMKilled: ei.OOMKilled,
			}
			restart, wait, err := c.RestartManager().ShouldRestart(ei.ExitCode, daemon.IsShuttingDown() || c.HasBeenManuallyStopped, time.Since(c.StartedAt))
			if err == nil && restart {
				c.RestartCount++
				c.SetRestarting(&exitStatus)
			} else {
				if ei.Error != nil {
					c.SetError(ei.Error)
				}
				c.SetStopped(&exitStatus)
				defer daemon.autoRemove(c)
			}
			defer c.Unlock() // needs to be called before autoRemove

			// cancel healthcheck here, they will be automatically
			// restarted if/when the container is started again
			daemon.stopHealthchecks(c)
			attributes := map[string]string{
				"exitCode": strconv.Itoa(int(ei.ExitCode)),
			}
			daemon.LogContainerEventWithAttributes(c, "die", attributes)
			daemon.Cleanup(c)
			daemon.setStateCounter(c)
			cpErr := c.CheckpointTo(daemon.containersReplica)

			if err == nil && restart {
				go func() {
					err := <-wait
					if err == nil {
						// daemon.netController is initialized when daemon is restoring containers.
						// But containerStart will use daemon.netController segment.
						// So to avoid panic at startup process, here must wait util daemon restore done.
						daemon.waitForStartupDone()
						if err = daemon.containerStart(c, "", "", false); err != nil {
							logrus.Debugf("failed to restart container: %+v", err)
						}
					}
					if err != nil {
						c.Lock()
						c.SetStopped(&exitStatus)
						daemon.setStateCounter(c)
						c.CheckpointTo(daemon.containersReplica)
						c.Unlock()
						defer daemon.autoRemove(c)
						if err != restartmanager.ErrRestartCanceled {
							logrus.Errorf("restartmanger wait error: %+v", err)
						}
					}
				}()
			}

			return cpErr
		}

		exitCode := 127
		if execConfig := c.ExecCommands.Get(ei.ProcessID); execConfig != nil {
			ec := int(ei.ExitCode)
			execConfig.Lock()
			defer execConfig.Unlock()
			execConfig.ExitCode = &ec
			execConfig.Running = false

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			execConfig.StreamConfig.Wait(ctx)
			cancel()

			if err := execConfig.CloseStreams(); err != nil {
				logrus.Errorf("failed to cleanup exec %s streams: %s", c.ID, err)
			}

			// remove the exec command from the container's store only and not the
			// daemon's store so that the exec command can be inspected.
			c.ExecCommands.Delete(execConfig.ID, execConfig.Pid)

			exitCode = ec
		}
		attributes := map[string]string{
			"execID":   ei.ProcessID,
			"exitCode": strconv.Itoa(exitCode),
		}
		daemon.LogContainerEventWithAttributes(c, "exec_die", attributes)
	case libcontainerdtypes.EventStart:
		c.Lock()
		defer c.Unlock()

		// This is here to handle start not generated by docker
		if !c.Running {
			c.SetRunning(int(ei.Pid), false)
			c.HasBeenManuallyStopped = false
			c.HasBeenStartedBefore = true
			daemon.setStateCounter(c)

			daemon.initHealthMonitor(c)

			if err := c.CheckpointTo(daemon.containersReplica); err != nil {
				return err
			}
			daemon.LogContainerEvent(c, "start")
		}

	case libcontainerdtypes.EventPaused:
		c.Lock()
		defer c.Unlock()

		if !c.Paused {
			c.Paused = true
			daemon.setStateCounter(c)
			daemon.updateHealthMonitor(c)
			if err := c.CheckpointTo(daemon.containersReplica); err != nil {
				return err
			}
			daemon.LogContainerEvent(c, "pause")
		}
	case libcontainerdtypes.EventResumed:
		c.Lock()
		defer c.Unlock()

		if c.Paused {
			c.Paused = false
			daemon.setStateCounter(c)
			daemon.updateHealthMonitor(c)

			if err := c.CheckpointTo(daemon.containersReplica); err != nil {
				return err
			}
			daemon.LogContainerEvent(c, "unpause")
		}
	}
	return nil
}

func (c *client) DeleteTask(ctx context.Context, containerID string) (uint32, time.Time, error) {
	p, err := c.getProcess(ctx, containerID, libcontainerdtypes.InitProcessName)
	if err != nil {
		return 255, time.Now(), nil
	}

	status, err := p.Delete(ctx)
	if err != nil {
		return 255, time.Now(), nil
	}
	return status.ExitCode(), status.ExitTime(), nil
}


// Delete deletes the task and its runtime state
// it returns the exit status of the task and any errors that were encountered
// during cleanup
func (t *task) Delete(ctx context.Context, opts ...ProcessDeleteOpts) (*ExitStatus, error) {
	
	for _, o := range opts {
		if err := o(ctx, t); err != nil {
			return nil, err
		}
	}
	status, err := t.Status(ctx)
	if err != nil && errdefs.IsNotFound(err) {
		return nil, err
	}
	switch status.Status {
	case Stopped, Unknown, "":
	case Created:
		if t.client.runtime == fmt.Sprintf("%s.%s", plugin.RuntimePlugin, "windows") {
			// On windows Created is akin to Stopped
			break
		}
		fallthrough
	default:
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "task must be stopped before deletion: %s", status.Status)
	}
	if t.io != nil {
		t.io.Cancel()
		t.io.Wait()
	}
	r, err := t.client.TaskService().Delete(ctx, &tasks.DeleteTaskRequest{
		ContainerID: t.id,
	})
	if err != nil {
		return nil, errdefs.FromGRPC(err)
	}
	// Only cleanup the IO after a successful Delete
	if t.io != nil {
		t.io.Close()
	}
	return &ExitStatus{code: r.ExitStatus, exitedAt: r.ExitedAt}, nil
}

//dockerd 发消息
func (c *tasksClient) Delete(ctx context.Context, in *DeleteTaskRequest, opts ...grpc.CallOption) (*DeleteResponse, error) {
	
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+":dockerd taskClient Delete: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "tid " +strconv.Itoa(unix.Gettid())+ "\n")
	file.Close()

	t1:=time.Now().UnixNano()

	out := new(DeleteResponse)
	err := c.cc.Invoke(ctx, "/containerd.services.tasks.v1.Tasks/Delete", in, out, opts...)

	t2:=time.Now().UnixNano()

	file,_= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString("dockerd taskClient delete time: "+strconv.FormatInt(t2-t1,10)+"\n")
	file.Close()

	if err != nil {
		return nil, err
	}
	return out, nil
}
//containerd接受信息
func _Tasks_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	
	var timeLayoutStr = "2006-01-02 15:04:05"
	
	filePath:="/root/containerd_log.txt"
	file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
	_,_=file.WriteString(time.Now().Format(timeLayoutStr)+":containerd _Tasks_Delete_Handler: pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "tid " +strconv.Itoa(unix.Gettid())+ "\n")
	
	file.Close()

	in := new(DeleteTaskRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TasksServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/containerd.services.tasks.v1.Tasks/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TasksServer).Delete(ctx, req.(*DeleteTaskRequest))
	}
	return interceptor(ctx, in, info, handler)
}



// runc处理函数在上面
func destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

func (c *linuxContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state.destroy()
}

func (b *stoppedState) destroy() error {
	return destroy(b.c)
}

type linuxContainer struct {
	id                   string
	root                 string
	config               *configs.Config
	cgroupManager        cgroups.Manager	//接口类型
	intelRdtManager      intelrdt.Manager
	initPath             string
	initArgs             []string
	initProcess          parentProcess
	initProcessStartTime uint64
	criuPath             string
	newuidmapPath        string
	newgidmapPath        string
	m                    sync.Mutex
	criuVersion          int
	state                containerState
	created              time.Time
}

type Namespaces []Namespace

// Namespace defines configuration for each namespace.  It specifies an
// alternate path that is able to be joined via setns.
type Namespace struct {
	Type NamespaceType `json:"type"`
	Path string        `json:"path"`
}

//主要就这个函数
func destroy(c *linuxContainer) error {
	if !c.config.Namespaces.Contains(configs.NEWPID) {	//namespace Type中包含 NEWPID(string)
		if err := signalAllProcesses(c.cgroupManager, unix.SIGKILL); err != nil {
			logrus.Warn(err)
		}
	}
	err := c.cgroupManager.Destroy()	//删除所有cgroup文件夹
	if c.intelRdtManager != nil {
		if ierr := c.intelRdtManager.Destroy(); err == nil {
			err = ierr
		}
	}
	if rerr := os.RemoveAll(c.root); err == nil {
		err = rerr
	}
	c.initProcess = nil
	//Hook中stop 为空，什么都没做
	if herr := runPoststopHooks(c); err == nil {
		err = herr
	}
	c.state = &stoppedState{c: c}
	return err
}

	// Hooks are a collection of actions to perform at various container lifecycle events.
	// CommandHooks are serialized to JSON, but other hooks are not.
	//Hooks *Hooks  //configs结构成员

type Hooks struct {
	// Prestart commands are executed after the container namespaces are created,
	// but before the user supplied command is executed from init.
	Prestart []Hook

	// Poststart commands are executed after the container init process starts.
	Poststart []Hook

	// Poststop commands are executed after the container init process exits.
	Poststop []Hook
}

type Hook interface {
	// Run executes the hook with the provided state.
	Run(*specs.State) error
}
type FuncHook struct {
	run func(*specs.State) error
}

func runPoststopHooks(c *linuxContainer) error {
	if c.config.Hooks != nil {
		s, err := c.currentOCIState()
		if err != nil {
			return err
		}
		//以下为空
		for _, hook := range c.config.Hooks.Poststop {
			//可以把Hook内容打印处理
			if err := hook.Run(s); err != nil {
				return err
			}
		}
	}
	return nil
}

//位于fs包，实现了位于cgroups包的Manager接口
type Manager struct {
	mu       sync.Mutex
	Cgroups  *configs.Cgroup
	Rootless bool // ignore permission-related errors
	Paths    map[string]string
}


func (m *Manager) Destroy() error {
	if m.Cgroups == nil || m.Cgroups.Paths != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := cgroups.RemovePaths(m.Paths); err != nil {
		return err
	}
	m.Paths = make(map[string]string)
	return nil
}

// RemovePaths iterates over the provided paths removing them.
// We trying to remove all paths five times with increasing delay between tries.
// If after all there are not removed cgroups - appropriate error will be
// returned.
func RemovePaths(paths map[string]string) (err error) {
	delay := 10 * time.Millisecond
	for i := 0; i < 5; i++ {
		if i != 0 {
			time.Sleep(delay)
			delay *= 2
		}
		for s, p := range paths {
			os.RemoveAll(p)		//删除文件夹
			// TODO: here probably should be logging
			_, err := os.Stat(p)	//获取文件属性
			// We need this strange way of checking cgroups existence because
			// RemoveAll almost always returns error, even on already removed
			// cgroups
			if os.IsNotExist(err) {		//已经删除
				delete(paths, s)	//从path删除键值s的对
			}
		}
		if len(paths) == 0 {
			return nil
		}
	}
	return fmt.Errorf("Failed to remove paths: %v", paths)
}


//第二个delete

//containerd
func _Containers_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteContainerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainersServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/containerd.services.containers.v1.Containers/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainersServer).Delete(ctx, req.(*DeleteContainerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func (s *service) Delete(ctx context.Context, req *api.DeleteContainerRequest) (*ptypes.Empty, error) {

	return s.local.Delete(ctx, req)
}

type local struct {
	containers.Store
	db        *metadata.DB
	publisher events.Publisher
}

func (l *local) Delete(ctx context.Context, req *api.DeleteContainerRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	if err := l.withStoreUpdate(ctx, func(ctx context.Context) error {
		return l.Store.Delete(ctx, req.ID)
	}); err != nil {
		return &ptypes.Empty{}, errdefs.ToGRPC(err)
	}

	if err := l.publisher.Publish(ctx, "/containers/delete", &eventstypes.ContainerDelete{
		ID: req.ID,
	}); err != nil {
		return &ptypes.Empty{}, err
	}

	return &ptypes.Empty{}, nil
}

func (l *local) withStoreUpdate(ctx context.Context, fn func(ctx context.Context) error) error {
	return l.db.Update(l.withStore(ctx, fn))
}
func (l *local) withStore(ctx context.Context, fn func(ctx context.Context) error) func(tx *bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		return fn(metadata.WithTransactionContext(ctx, tx))
	}
}

// Update runs a writable transaction on the metadata store.
func (m *DB) Update(fn func(*bolt.Tx) error) error {
	m.wlock.RLock()
	defer m.wlock.RUnlock()
	err := m.db.Update(fn)
	if err == nil {
		dirty := atomic.LoadUint32(&m.dirty) > 0
		for _, fn := range m.mutationCallbacks {
			fn(dirty)
		}
	}

	return err
}
