// DaemonCli represents the daemon CLI.
type DaemonCli struct {
	*config.Config
	configFile *string
	flags      *pflag.FlagSet

	api             *apiserver.Server
	d               *daemon.Daemon
	authzMiddleware *authorization.Middleware // authzMiddleware enables to dynamically reload the authorization plugins
}

//yeah! find the main
func main() {
	//reexec 存在的作用 是:协调 execdriver 与容器创建时 dockerinit 这两者的关系
	if reexec.Init() {
		return
	}

	// initial log formatting; this setting is updated after the daemon configuration is loaded.
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: jsonmessage.RFC3339NanoFixed,
		FullTimestamp:   true,
	})

	// Set terminal emulation based on platform as required.
	_, stdout, stderr := term.StdStreams()

	initLogging(stdout, stderr)

	//错误退出
	onError := func(err error) {
		fmt.Fprintf(stderr, "%s\n", err)
		os.Exit(1)
	}

	cmd, err := newDaemonCommand()  //生成cmd，daemon只存在根命令，没有子命令，以及配置
	if err != nil {
		onError(err)
	}
	cmd.SetOutput(stdout)
	if err := cmd.Execute(); err != nil {
		onError(err)
	}
}

func newDaemonCommand() (*cobra.Command, error) {
	opts := newDaemonOptions(config.New())

	cmd := &cobra.Command{
		Use:           "dockerd [OPTIONS]",
		Short:         "A self-sufficient runtime for containers.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.flags = cmd.Flags()
			return runDaemon(opts)  //there
		},
		DisableFlagsInUseLine: true,
		Version:               fmt.Sprintf("%s, build %s", dockerversion.Version, dockerversion.GitCommit),
	}
	cli.SetupRootCommand(cmd)

	flags := cmd.Flags()
	flags.BoolP("version", "v", false, "Print version information and quit")
	defaultDaemonConfigFile, err := getDefaultDaemonConfigFile()
	if err != nil {
		return nil, err
	}
	flags.StringVar(&opts.configFile, "config-file", defaultDaemonConfigFile, "Daemon configuration file")
	opts.InstallFlags(flags)
	if err := installConfigFlags(opts.daemonConfig, flags); err != nil {
		return nil, err
	}
	installServiceFlags(flags)

	return cmd, nil
}

//该函数还需测试
func runDaemon(opts *daemonOptions) error {
	daemonCli := NewDaemonCli()
	return daemonCli.start(opts)	//start是一个阻塞方法
}


func (cli *DaemonCli) start(opts *daemonOptions) (err error) {
	stopc := make(chan bool)
	defer close(stopc)

	// warn from uuid package when running the daemon
	uuid.Loggerf = logrus.Warnf

	opts.SetDefaultOptions(opts.flags)

	if cli.Config, err = loadDaemonCliConfig(opts); err != nil {
		return err
	}
	warnOnDeprecatedConfigOptions(cli.Config)

	if err := configureDaemonLogs(cli.Config); err != nil {
		return err
	}

	logrus.Info("Starting up")

	cli.configFile = &opts.configFile
	cli.flags = opts.flags

	if cli.Config.Debug {
		debug.Enable()
	}

	if cli.Config.Experimental {
		logrus.Warn("Running experimental build")
		if cli.Config.IsRootless() {
			logrus.Warn("Running in rootless mode. Cgroups, AppArmor, and CRIU are disabled.")
		}
		if rootless.RunningWithRootlessKit() {
			logrus.Info("Running with RootlessKit integration")
			if !cli.Config.IsRootless() {
				return fmt.Errorf("rootless mode needs to be enabled for running with RootlessKit")
			}
		}
	} else {
		if cli.Config.IsRootless() {
			return fmt.Errorf("rootless mode is supported only when running in experimental mode")
		}
	}
	// return human-friendly error before creating files
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("dockerd needs to be started with root. To see how to run dockerd in rootless mode with unprivileged user, see the documentation")
	}

	system.InitLCOW(cli.Config.Experimental)

	if err := setDefaultUmask(); err != nil {
		return err
	}

	// Create the daemon root before we create ANY other files (PID, or migrate keys)
	// to ensure the appropriate ACL is set (particularly relevant on Windows)
	if err := daemon.CreateDaemonRoot(cli.Config); err != nil {
		return err
	}

	if err := system.MkdirAll(cli.Config.ExecRoot, 0700); err != nil {
		return err
	}

	potentiallyUnderRuntimeDir := []string{cli.Config.ExecRoot}

	if cli.Pidfile != "" {
		pf, err := pidfile.New(cli.Pidfile)
		if err != nil {
			return errors.Wrap(err, "failed to start daemon")
		}
		potentiallyUnderRuntimeDir = append(potentiallyUnderRuntimeDir, cli.Pidfile)
		defer func() {
			if err := pf.Remove(); err != nil {
				logrus.Error(err)
			}
		}()
	}

	if cli.Config.IsRootless() {
		// Set sticky bit if XDG_RUNTIME_DIR is set && the file is actually under XDG_RUNTIME_DIR
		if _, err := homedir.StickRuntimeDirContents(potentiallyUnderRuntimeDir); err != nil {
			// StickRuntimeDirContents returns nil error if XDG_RUNTIME_DIR is just unset
			logrus.WithError(err).Warn("cannot set sticky bit on files under XDG_RUNTIME_DIR")
		}
	}

	serverConfig, err := newAPIServerConfig(cli)
	if err != nil {
		return errors.Wrap(err, "failed to create API server")
	}

	//根据serverConfig创建API Server对象。
	//apiserver 就是server包的别名
	cli.api = apiserver.New(serverConfig)		

	hosts, err := loadListeners(cli, serverConfig)
	if err != nil {
		return errors.Wrap(err, "failed to load listeners")
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForContainerDShutdown, err := cli.initContainerD(ctx)
	if waitForContainerDShutdown != nil {
		defer waitForContainerDShutdown(10 * time.Second)
	}
	if err != nil {
		cancel()
		return err
	}
	defer cancel()

	//接下来声明监听系统的一些终止信号，如监听到这些信息，就停止 DaemonCli
	signal.Trap(func() {
		cli.stop()
		<-stopc // wait for daemonCli.start() to return
	}, logrus.StandardLogger())

	// Notify that the API is active, but before daemon is set up.
	preNotifySystem()

	pluginStore := plugin.NewStore()

	//给API Server注册一些中间件，这些中间件主要进行版本兼容性检查、添加CORS跨站点请求相关响应头、对请求进行认证
	if err := cli.initMiddlewares(cli.api, serverConfig, pluginStore); err != nil {
		logrus.Fatalf("Error creating middlewares: %v", err)
	}

	//创建daemon对象
	d, err := daemon.NewDaemon(ctx, cli.Config, pluginStore)	//there
	if err != nil {
		return errors.Wrap(err, "failed to start daemon")
	}

	d.StoreHosts(hosts)

	// validate after NewDaemon has restored enabled plugins. Don't change order.
	if err := validateAuthzPlugins(cli.Config.AuthorizationPlugins, pluginStore); err != nil {
		return errors.Wrap(err, "failed to validate authorization plugin")
	}

	cli.d = d

	if err := cli.startMetricsServer(cli.Config.MetricsAddress); err != nil {
		return err
	}

	c, err := createAndStartCluster(cli, d)
	if err != nil {
		logrus.Fatalf("Error starting cluster component: %v", err)
	}

	// Restart all autostart containers which has a swarm endpoint
	// and is not yet running now that we have successfully
	// initialized the cluster.
	//docker还集成了swarm的相关功能，这里将自动启动安装有swarm endpoint的容器。
	d.RestartSwarmContainers()

	logrus.Info("Daemon has completed initialization")

	routerOptions, err := newRouterOptions(cli.Config, d)
	if err != nil {
		return err
	}
	routerOptions.api = cli.api
	routerOptions.cluster = c

	//初始化API Server的路由
	initRouter(routerOptions)

	go d.ProcessClusterNotifications(ctx, c.GetWatchStream())

	//当监听到系统信号SIGHUP，就会重新加载daemon程序的配置
	cli.setupConfigReloadTrap()

	// The serve API routine never exits unless an error occurs
	// We need to start it as a goroutine and wait on it so
	// daemon doesn't exit
	//创建goroutine使API Server开始对外提供服务，并在该goroutine里等待API Server停止
	serveAPIWait := make(chan error)
	go cli.api.Wait(serveAPIWait)  // api 类型*apiserver.Server

	// after the daemon is done setting up we can notify systemd api
	//调用操作系统的systemd服务，docker的daemon进程已成功启动。 
	notifySystem()

	// Daemon is fully initialized and handling API traffic
	// Wait for serve API to complete
	//使main goroutine阻塞住了，这样daemon进程就不会退出。
	//一旦阻塞解除了，也就意味着daemon进程需要退出了，这时做一些清理工作。
	errAPI := <-serveAPIWait
	c.Cleanup()

	shutdownDaemon(d)

	// Stop notification processing and any background processes
	cancel()

	if errAPI != nil {
		return errors.Wrap(errAPI, "shutting down due to ServeAPI error")
	}

	logrus.Info("Daemon shutdown complete")
	return nil
}

// Server contains instance details for the server
type Server struct {
	cfg         *Config
	servers     []*HTTPServer	//最后调用servers中的server函数，里面也有listener
	routers     []router.Router
	middlewares []middleware.Middleware
}


// HTTPServer contains an instance of http server and the listener.
// srv *http.Server, contains configuration to create an http server and a mux router with all api end points.
// l   net.Listener, is a TCP or Socket listener that dispatches incoming request to the router.
type HTTPServer struct {
	srv *http.Server
	l   net.Listener
}

// New returns a new instance of the server based on the specified configuration.
// It allocates resources which will be needed for ServeAPI(ports, unix-sockets).
func New(cfg *Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

//cli.api 类型*apiserver.Server
//初始化 server中的servers(* HTTPServer)
func loadListeners(cli *DaemonCli, serverConfig *apiserver.Config) ([]string, error) {
	var hosts []string
	seen := make(map[string]struct{}, len(cli.Config.Hosts))

	for i := 0; i < len(cli.Config.Hosts); i++ {
		var err error
		if cli.Config.Hosts[i], err = dopts.ParseHost(cli.Config.TLS, honorXDG, cli.Config.Hosts[i]); err != nil {
			return nil, errors.Wrapf(err, "error parsing -H %s", cli.Config.Hosts[i])
		}
		if _, ok := seen[cli.Config.Hosts[i]]; ok {
			continue
		}
		seen[cli.Config.Hosts[i]] = struct{}{}

		protoAddr := cli.Config.Hosts[i]
		protoAddrParts := strings.SplitN(protoAddr, "://", 2)
		if len(protoAddrParts) != 2 {
			return nil, fmt.Errorf("bad format %s, expected PROTO://ADDR", protoAddr)
		}

		proto := protoAddrParts[0]
		addr := protoAddrParts[1]

		// It's a bad idea to bind to TCP without tlsverify.
		if proto == "tcp" && (serverConfig.TLSConfig == nil || serverConfig.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert) {
			logrus.Warn("[!] DON'T BIND ON ANY IP ADDRESS WITHOUT setting --tlsverify IF YOU DON'T KNOW WHAT YOU'RE DOING [!]")
		}
		ls, err := listeners.Init(proto, addr, serverConfig.SocketGroup, serverConfig.TLSConfig)
		if err != nil {
			return nil, err
		}
		// If we're binding to a TCP port, make sure that a container doesn't try to use it.
		if proto == "tcp" {
			if err := allocateDaemonPort(addr); err != nil {
				return nil, err
			}
		}
		logrus.Debugf("Listener created for HTTP on %s (%s)", proto, addr)
		hosts = append(hosts, protoAddrParts[1])
		cli.api.Accept(addr, ls...)
	}

	return hosts, nil
}

// Accept sets a listener the server accepts connections into.
func (s *Server) Accept(addr string, listeners ...net.Listener) {
	for _, listener := range listeners {
		httpServer := &HTTPServer{
			srv: &http.Server{
				Addr: addr,
			},
			l: listener,
		}
		s.servers = append(s.servers, httpServer)
	}
}


// Middleware is an interface to allow the use of ordinary functions as Docker API filters.
// Any struct that has the appropriate signature can be registered as a middleware.
//exper 与 version 使用
type Middleware interface {
	WrapHandler(func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error) func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error
}

// UseMiddleware appends a new middleware to the request chain.
// This needs to be called before the API routes are configured.
func (s *Server) UseMiddleware(m middleware.Middleware) {
	s.middlewares = append(s.middlewares, m)
}


//newmiddleware使用
// Middleware uses a list of plugins to
// handle authorization in the API requests.
type Middleware struct {
	mu      sync.Mutex
	plugins []Plugin
}

// NewMiddleware creates a new Middleware
// with a slice of plugins names.
func NewMiddleware(names []string, pg plugingetter.PluginGetter) *Middleware {
	SetPluginGetter(pg)
	return &Middleware{
		plugins: newPlugins(names),
	}
}

type Plugin interface {
    Name() string
    AuthZRequest(*Request) (*Response, error)
    AuthZResponse(*Request) (*Response, error)
}

// TODO: remove this from cli and return the authzMiddleware
func (cli *DaemonCli) initMiddlewares(s *apiserver.Server, cfg *apiserver.Config, pluginStore plugingetter.PluginGetter) error {
	v := cfg.Version
	
	//newex返回string true/false
	exp := middleware.NewExperimentalMiddleware(cli.Config.Experimental)
	s.UseMiddleware(exp)

	vm := middleware.NewVersionMiddleware(v, api.DefaultVersion, api.MinVersion)
	s.UseMiddleware(vm)

	if cfg.CorsHeaders != "" {
		c := middleware.NewCORSMiddleware(cfg.CorsHeaders)
		s.UseMiddleware(c)
	}

	cli.authzMiddleware = authorization.NewMiddleware(cli.Config.AuthorizationPlugins, pluginStore)
	cli.Config.AuthzMiddleware = cli.authzMiddleware
	s.UseMiddleware(cli.authzMiddleware)
	return nil
}

// Wait blocks the server goroutine until it exits.
// It sends an error message if there is any error during
// the API execution.
func (s *Server) Wait(waitChan chan error) {
	if err := s.serveAPI(); err != nil {
		logrus.Errorf("ServeAPI error: %v", err)
		waitChan <- err
		return
	}
	waitChan <- nil
}


// Serve starts listening for inbound requests.
func (s *HTTPServer) Serve() error {
	return s.srv.Serve(s.l)
}

// serveAPI loops through all initialized servers and spawns goroutine
// with Serve method for each. It sets createMux() as Handler also.
func (s *Server) serveAPI() error {
	var chErrors = make(chan error, len(s.servers))
	for _, srv := range s.servers {
		srv.srv.Handler = s.createMux()
		go func(srv *HTTPServer) {
			var err error
			logrus.Infof("pid %d ppid %d API listen on %s",os.Getpid(), os.Getppid(), srv.l.Addr())
			
			//同样阻塞
			if err = srv.Serve(); err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			chErrors <- err
		}(srv)
	}

	for range s.servers {
		err := <-chErrors
		if err != nil {
			return err
		}
	}
	return nil
}

// createMux initializes the main router the server uses.
func (s *Server) createMux() *mux.Router {
	m := mux.NewRouter()

	logrus.Debug("Registering routers")
	for _, apiRouter := range s.routers {		//[]router.Router
		for _, r := range apiRouter.Routes() {
			//r.Method() http方法 r.Path()方法后路径  r.Handler()处理方法
			f := s.makeHTTPHandler(r.Handler())

			logrus.Debugf("Registering %s, %s", r.Method(), r.Path())
			m.Path(versionMatcher + r.Path()).Methods(r.Method()).Handler(f)
			m.Path(r.Path()).Methods(r.Method()).Handler(f)
		}
	}

	debugRouter := debug.NewRouter()
	s.routers = append(s.routers, debugRouter)
	for _, r := range debugRouter.Routes() {
		f := s.makeHTTPHandler(r.Handler())
		m.Path("/debug" + r.Path()).Handler(f)
	}

	notFoundHandler := httputils.MakeErrorHandler(pageNotFoundError{})
	m.HandleFunc(versionMatcher+"/{path:.*}", notFoundHandler)
	m.NotFoundHandler = notFoundHandler
	m.MethodNotAllowedHandler = notFoundHandler

	return m
}

func (s *Server) makeHTTPHandler(handler httputils.APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Define the context that we'll pass around to share info
		// like the docker-request-id.
		//
		// The 'context' will be used for global data that should
		// apply to all requests. Data that is specific to the
		// immediate function being called should still be passed
		// as 'args' on the function call.

		// use intermediate variable to prevent "should not use basic type
		// string as key in context.WithValue" golint errors
		ctx := context.WithValue(r.Context(), dockerversion.UAStringKey{}, r.Header.Get("User-Agent"))
		r = r.WithContext(ctx)
		handlerFunc := s.handlerWithGlobalMiddlewares(handler)

		vars := mux.Vars(r)
		if vars == nil {
			vars = make(map[string]string)
		}

		if err := handlerFunc(ctx, w, r, vars); err != nil {
			statusCode := errdefs.GetHTTPErrorStatusCode(err)
			if statusCode >= 500 {
				logrus.Errorf("Handler for %s %s returned error: %v", r.Method, r.URL.Path, err)
			}
			httputils.MakeErrorHandler(err)(w, r)
		}
	}
}

// handlerWithGlobalMiddlewares wraps the handler function for a request with
// the server's global middlewares. The order of the middlewares is backwards,
// meaning that the first in the list will be evaluated last.
func (s *Server) handlerWithGlobalMiddlewares(handler httputils.APIFunc) httputils.APIFunc {
	next := handler

	for _, m := range s.middlewares {
		next = m.WrapHandler(next)
	}

	if s.cfg.Logging && logrus.GetLevel() == logrus.DebugLevel {
		next = middleware.DebugRequestMiddleware(next)
	}

	return next
}

// WrapHandler returns a new handler function wrapping the previous one in the request chain.
func (m *Middleware) WrapHandler(handler func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error) func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
		plugins := m.getAuthzPlugins()
		if len(plugins) == 0 {
			return handler(ctx, w, r, vars)
		}

		user := ""
		userAuthNMethod := ""

		// Default authorization using existing TLS connection credentials
		// FIXME: Non trivial authorization mechanisms (such as advanced certificate validations, kerberos support
		// and ldap) will be extracted using AuthN feature, which is tracked under:
		// https://github.com/docker/docker/pull/20883
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			user = r.TLS.PeerCertificates[0].Subject.CommonName
			userAuthNMethod = "TLS"
		}

		authCtx := NewCtx(plugins, user, userAuthNMethod, r.Method, r.RequestURI)

		if err := authCtx.AuthZRequest(w, r); err != nil {
			logrus.Errorf("AuthZRequest for %s %s returned error: %s", r.Method, r.RequestURI, err)
			return err
		}

		rw := NewResponseModifier(w)

		var errD error

		if errD = handler(ctx, rw, r, vars); errD != nil {
			logrus.Errorf("Handler for %s %s returned error: %s", r.Method, r.RequestURI, errD)
		}

		// There's a chance that the authCtx.plugins was updated. One of the reasons
		// this can happen is when an authzplugin is disabled.
		plugins = m.getAuthzPlugins()
		if len(plugins) == 0 {
			logrus.Debug("There are no authz plugins in the chain")
			return nil
		}

		authCtx.plugins = plugins

		if err := authCtx.AuthZResponse(rw, r); errD == nil && err != nil {
			logrus.Errorf("AuthZResponse for %s %s returned error: %s", r.Method, r.RequestURI, err)
			return err
		}

		if errD != nil {
			return errD
		}

		return nil
	}
}
/**
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon 
 * NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon NewDaemon
 * 
 **/

// NewDaemon sets up everything for the daemon to be able to service
// requests from the webserver.
func NewDaemon(ctx context.Context, config *config.Config, pluginStore *plugin.Store) (daemon *Daemon, err error) {
	setDefaultMtu(config)

	//daemon程序在pull镜像等操作时，需要与registry服务交互，这里即创建了registryService对象，用于与registry服务交互
	registryService, err := registry.NewService(config.ServiceOptions)
	if err != nil {
		return nil, err
	}

	// Ensure that we have a correct root key limit for launching containers.
	if err := ModifyRootKeyLimit(); err != nil {
		logrus.Warnf("unable to modify root key limit, number of containers could be limited by this quota: %v", err)
	}

	// Ensure we have compatible and valid configuration options
	if err := verifyDaemonSettings(config); err != nil {
		return nil, err
	}

	// Do we have a disabled network?
	config.DisableBridge = isBridgeNetworkDisabled(config)

	// Setup the resolv.conf
	setupResolvConf(config)

	// Verify the platform is supported as a daemon
	if !platformSupported {
		return nil, errSystemNotSupported
	}

	// Validate platform-specific requirements
	if err := checkSystem(); err != nil {
		return nil, err
	}

	//docker支持用户空间重映射特性，这里就是在解析与之相关的userns-remap参数。
	//docker用户空间重映射特性其实就是将容器内的用户映射为宿主机上的普通用户，这个主要是为了加强容器安全的
	idMapping, err := setupRemappedRoot(config)
	if err != nil {
		return nil, err
	}
	rootIDs := idMapping.RootPair()
	if err := setupDaemonProcess(config); err != nil {
		return nil, err
	}

	//对存储目录进行必要的权限调整、
	//对daemon进程的 oom_score_adj 参数进行必要的调整（减小daemon进程被OS杀掉的可能性）、创建临时目录。
	// set up the tmpDir to use a canonical path
	tmp, err := prepareTempDir(config.Root, rootIDs)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the TempDir under %s: %s", config.Root, err)
	}
	realTmp, err := fileutils.ReadSymlinkedDirectory(tmp)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the full path to the TempDir (%s): %s", tmp, err)
	}
	if isWindows {
		if _, err := os.Stat(realTmp); err != nil && os.IsNotExist(err) {
			if err := system.MkdirAll(realTmp, 0700); err != nil {
				return nil, fmt.Errorf("Unable to create the TempDir (%s): %s", realTmp, err)
			}
		}
		os.Setenv("TEMP", realTmp)
		os.Setenv("TMP", realTmp)
	} else {
		os.Setenv("TMPDIR", realTmp)
	}

	d := &Daemon{
		configStore: config,
		PluginStore: pluginStore,
		startupDone: make(chan struct{}),
	}

	// Ensure the daemon is properly shutdown if there is a failure during
	// initialization
	defer func() {
		if err != nil {
			if err := d.Shutdown(); err != nil {
				logrus.Error(err)
			}
		}
	}()

	if err := d.setGenericResources(config); err != nil {
		return nil, err
	}
	// set up SIGUSR1 handler on Unix-like systems, or a Win32 global event
	// on Windows to dump Go routine stacks
	stackDumpDir := config.Root
	if execRoot := config.GetExecRoot(); execRoot != "" {
		stackDumpDir = execRoot
	}
	d.setupDumpStackTrap(stackDumpDir)

	if err := d.setupSeccompProfile(); err != nil {
		return nil, err
	}

	// Set the default isolation mode (only applicable on Windows)
	if err := d.setDefaultIsolation(); err != nil {
		return nil, fmt.Errorf("error setting default isolation mode: %v", err)
	}

	if err := configureMaxThreads(config); err != nil {
		logrus.Warnf("Failed to configure golang's threads limit: %v", err)
	}

	// ensureDefaultAppArmorProfile does nothing if apparmor is disabled
	if err := ensureDefaultAppArmorProfile(); err != nil {
		logrus.Errorf(err.Error())
	}

	daemonRepo := filepath.Join(config.Root, "containers")
	if err := idtools.MkdirAllAndChown(daemonRepo, 0700, rootIDs); err != nil {
		return nil, err
	}

	// Create the directory where we'll store the runtime scripts (i.e. in
	// order to support runtimeArgs)
	daemonRuntimes := filepath.Join(config.Root, "runtimes")
	if err := system.MkdirAll(daemonRuntimes, 0700); err != nil {
		return nil, err
	}
	if err := d.loadRuntimes(); err != nil {
		return nil, err
	}

	if isWindows {
		if err := system.MkdirAll(filepath.Join(config.Root, "credentialspecs"), 0); err != nil {
			return nil, err
		}
	}

	// On Windows we don't support the environment variable, or a user supplied graphdriver
	// as Windows has no choice in terms of which graphdrivers to use. It's a case of
	// running Windows containers on Windows - windowsfilter, running Linux containers on Windows,
	// lcow. Unix platforms however run a single graphdriver for all containers, and it can
	// be set through an environment variable, a daemon start parameter, or chosen through
	// initialization of the layerstore through driver priority order for example.
	d.graphDrivers = make(map[string]string)
	layerStores := make(map[string]layer.Store)
	if isWindows {
		d.graphDrivers[runtime.GOOS] = "windowsfilter"
		if system.LCOWSupported() {
			d.graphDrivers["linux"] = "lcow"
		}
	} else {
		driverName := os.Getenv("DOCKER_DRIVER")
		if driverName == "" {
			driverName = config.GraphDriver
		} else {
			logrus.Infof("Setting the storage driver from the $DOCKER_DRIVER environment variable (%s)", driverName)
		}
		d.graphDrivers[runtime.GOOS] = driverName // May still be empty. Layerstore init determines instead.
	}

	d.RegistryService = registryService
	logger.RegisterPluginGetter(d.PluginStore)

	metricsSockPath, err := d.listenMetricsSock()
	if err != nil {
		return nil, err
	}
	registerMetricsPluginCallback(d.PluginStore, metricsSockPath)

	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = 3 * time.Second
	connParams := grpc.ConnectParams{
		Backoff: backoffConfig,
	}
	gopts := []grpc.DialOption{
		// WithBlock makes sure that the following containerd request
		// is reliable.
		//
		// NOTE: In one edge case with high load pressure, kernel kills
		// dockerd, containerd and containerd-shims caused by OOM.
		// When both dockerd and containerd restart, but containerd
		// will take time to recover all the existing containers. Before
		// containerd serving, dockerd will failed with gRPC error.
		// That bad thing is that restore action will still ignore the
		// any non-NotFound errors and returns running state for
		// already stopped container. It is unexpected behavior. And
		// we need to restart dockerd to make sure that anything is OK.
		//
		// It is painful. Add WithBlock can prevent the edge case. And
		// n common case, the containerd will be serving in shortly.
		// It is not harm to add WithBlock for containerd connection.
		grpc.WithBlock(),

		grpc.WithInsecure(),
		grpc.WithConnectParams(connParams),
		grpc.WithContextDialer(dialer.ContextDialer),

		// TODO(stevvooe): We may need to allow configuration of this on the client.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaults.DefaultMaxRecvMsgSize)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(defaults.DefaultMaxSendMsgSize)),
	}
	if config.ContainerdAddr != "" {
		d.containerdCli, err = containerd.New(config.ContainerdAddr, containerd.WithDefaultNamespace(config.ContainerdNamespace), containerd.WithDialOpts(gopts), containerd.WithTimeout(60*time.Second))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to dial %q", config.ContainerdAddr)
		}
	}

	createPluginExec := func(m *plugin.Manager) (plugin.Executor, error) {
		var pluginCli *containerd.Client

		// Windows is not currently using containerd, keep the
		// client as nil
		if config.ContainerdAddr != "" {
			pluginCli, err = containerd.New(config.ContainerdAddr, containerd.WithDefaultNamespace(config.ContainerdPluginNamespace), containerd.WithDialOpts(gopts), containerd.WithTimeout(60*time.Second))
			if err != nil {
				return nil, errors.Wrapf(err, "failed to dial %q", config.ContainerdAddr)
			}
		}

		return pluginexec.New(ctx, getPluginExecRoot(config.Root), pluginCli, config.ContainerdPluginNamespace, m, d.useShimV2())
	}

	// Plugin system initialization should happen before restore. Do not change order.
	d.pluginManager, err = plugin.NewManager(plugin.ManagerConfig{
		Root:               filepath.Join(config.Root, "plugins"),
		ExecRoot:           getPluginExecRoot(config.Root),
		Store:              d.PluginStore,
		CreateExecutor:     createPluginExec,
		RegistryService:    registryService,
		LiveRestoreEnabled: config.LiveRestoreEnabled,
		LogPluginEvent:     d.LogPluginEvent, // todo: make private
		AuthzMiddleware:    config.AuthzMiddleware,
	})
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create plugin manager")
	}

	if err := d.setupDefaultLogConfig(); err != nil {
		return nil, err
	}

	for operatingSystem, gd := range d.graphDrivers {
		layerStores[operatingSystem], err = layer.NewStoreFromOptions(layer.StoreOptions{
			Root:                      config.Root,
			MetadataStorePathTemplate: filepath.Join(config.Root, "image", "%s", "layerdb"),
			GraphDriver:               gd,
			GraphDriverOptions:        config.GraphOptions,
			IDMapping:                 idMapping,
			PluginGetter:              d.PluginStore,
			ExperimentalEnabled:       config.Experimental,
			OS:                        operatingSystem,
		})
		if err != nil {
			return nil, err
		}

		// As layerstore initialization may set the driver
		d.graphDrivers[operatingSystem] = layerStores[operatingSystem].DriverName()
	}

	// Configure and validate the kernels security support. Note this is a Linux/FreeBSD
	// operation only, so it is safe to pass *just* the runtime OS graphdriver.
	if err := configureKernelSecuritySupport(config, d.graphDrivers[runtime.GOOS]); err != nil {
		return nil, err
	}

	imageRoot := filepath.Join(config.Root, "image", d.graphDrivers[runtime.GOOS])
	ifs, err := image.NewFSStoreBackend(filepath.Join(imageRoot, "imagedb"))
	if err != nil {
		return nil, err
	}

	lgrMap := make(map[string]image.LayerGetReleaser)
	for os, ls := range layerStores {
		lgrMap[os] = ls
	}
	imageStore, err := image.NewImageStore(ifs, lgrMap)
	if err != nil {
		return nil, err
	}

	d.volumes, err = volumesservice.NewVolumeService(config.Root, d.PluginStore, rootIDs, d)
	if err != nil {
		return nil, err
	}

	trustKey, err := loadOrCreateTrustKey(config.TrustKeyPath)
	if err != nil {
		return nil, err
	}

	trustDir := filepath.Join(config.Root, "trust")

	if err := system.MkdirAll(trustDir, 0700); err != nil {
		return nil, err
	}

	// We have a single tag/reference store for the daemon globally. However, it's
	// stored under the graphdriver. On host platforms which only support a single
	// container OS, but multiple selectable graphdrivers, this means depending on which
	// graphdriver is chosen, the global reference store is under there. For
	// platforms which support multiple container operating systems, this is slightly
	// more problematic as where does the global ref store get located? Fortunately,
	// for Windows, which is currently the only daemon supporting multiple container
	// operating systems, the list of graphdrivers available isn't user configurable.
	// For backwards compatibility, we just put it under the windowsfilter
	// directory regardless.
	refStoreLocation := filepath.Join(imageRoot, `repositories.json`)
	rs, err := refstore.NewReferenceStore(refStoreLocation)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create reference store repository: %s", err)
	}

	distributionMetadataStore, err := dmetadata.NewFSMetadataStore(filepath.Join(imageRoot, "distribution"))
	if err != nil {
		return nil, err
	}

	// Discovery is only enabled when the daemon is launched with an address to advertise.  When
	// initialized, the daemon is registered and we can store the discovery backend as it's read-only
	if err := d.initDiscovery(config); err != nil {
		return nil, err
	}

	sysInfo := sysinfo.New(false)
	// Check if Devices cgroup is mounted, it is hard requirement for container security,
	// on Linux.
	if runtime.GOOS == "linux" && !sysInfo.CgroupDevicesEnabled {
		return nil, errors.New("Devices cgroup isn't mounted")
	}

	d.ID = trustKey.PublicKey().KeyID()
	d.repository = daemonRepo
	d.containers = container.NewMemoryStore()
	if d.containersReplica, err = container.NewViewDB(); err != nil {
		return nil, err
	}
	d.execCommands = exec.NewStore()
	d.idIndex = truncindex.NewTruncIndex([]string{})
	d.statsCollector = d.newStatsCollector(1 * time.Second)

	d.EventsService = events.New()
	d.root = config.Root
	d.idMapping = idMapping
	d.seccompEnabled = sysInfo.Seccomp
	d.apparmorEnabled = sysInfo.AppArmor

	d.linkIndex = newLinkIndex()

	// TODO: imageStore, distributionMetadataStore, and ReferenceStore are only
	// used above to run migration. They could be initialized in ImageService
	// if migration is called from daemon/images. layerStore might move as well.
	d.imageService = images.NewImageService(images.ImageServiceConfig{
		ContainerStore:            d.containers,
		DistributionMetadataStore: distributionMetadataStore,
		EventsService:             d.EventsService,
		ImageStore:                imageStore,
		LayerStores:               layerStores,
		MaxConcurrentDownloads:    *config.MaxConcurrentDownloads,
		MaxConcurrentUploads:      *config.MaxConcurrentUploads,
		MaxDownloadAttempts:       *config.MaxDownloadAttempts,
		ReferenceStore:            rs,
		RegistryService:           registryService,
		TrustKey:                  trustKey,
	})

	go d.execCommandGC()


	//创建与containerd通信的对象，包括发送信号的signalprocess
	d.containerd, err = libcontainerd.NewClient(ctx, d.containerdCli, filepath.Join(config.ExecRoot, "containerd"), config.ContainerdNamespace, d, d.useShimV2())
	if err != nil {
		return nil, err
	}

	if err := d.restore(); err != nil {
		return nil, err
	}
	close(d.startupDone)

	info := d.SystemInfo()

	engineInfo.WithValues(
		dockerversion.Version,
		dockerversion.GitCommit,
		info.Architecture,
		info.Driver,
		info.KernelVersion,
		info.OperatingSystem,
		info.OSType,
		info.OSVersion,
		info.ID,
	).Set(1)
	engineCpus.Set(float64(info.NCPU))
	engineMemory.Set(float64(info.MemTotal))

	gd := ""
	for os, driver := range d.graphDrivers {
		if len(gd) > 0 {
			gd += ", "
		}
		gd += driver
		if len(d.graphDrivers) > 1 {
			gd = fmt.Sprintf("%s (%s)", gd, os)
		}
	}
	logrus.WithFields(logrus.Fields{
		"version":        dockerversion.Version,
		"commit":         dockerversion.GitCommit,
		"graphdriver(s)": gd,
	}).Info("Docker daemon")

	return d, nil
}