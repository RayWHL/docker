/**
 * delete 上层调用分析
 * 
 * */

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

			t1:=time.Now().UnixNano()

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
			t2:=time.Now().UnixNano()

			file,_= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
			_,_=file.WriteString("exitevent time: "+strconv.FormatInt(t2-t1,10)+"\n")
		
			file.Close()
	
			return cpErr
		}

		var timeLayoutStr = "2006-01-02 15:04:05"
	
		filePath:="/root/containerd_log.txt"
		file,_:= os.OpenFile(filePath, os.O_RDWR|os.O_APPEND , 777)
		_,_=file.WriteString(time.Now().Format(timeLayoutStr)+": daemon ProcessEvent not if(delete): pid:" +strconv.Itoa(os.Getpid())+" ppid:" +strconv.Itoa(os.Getppid())+ "tid " +strconv.Itoa(unix.Gettid())+ "\n")
	
		file.Close()

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


func (c *client) processEvent(ctx context.Context, et libcontainerdtypes.EventType, ei libcontainerdtypes.EventInfo) {
	c.eventQ.Append(ei.ContainerID, func() {
		err := c.backend.ProcessEvent(ei.ContainerID, et, ei)
		if err != nil {
			c.logger.WithError(err).WithFields(logrus.Fields{
				"container":  ei.ContainerID,
				"event":      et,
				"event-info": ei,
			}).Error("failed to process event")
		}

		if et == libcontainerdtypes.EventExit && ei.ProcessID != ei.ContainerID {
			p, err := c.getProcess(ctx, ei.ContainerID, ei.ProcessID)
			if err != nil {

				c.logger.WithError(errors.New("no such process")).
					WithFields(logrus.Fields{
						"error":     err,
						"container": ei.ContainerID,
						"process":   ei.ProcessID,
					}).Error("exit event")
				return
			}

			ctr, err := c.getContainer(ctx, ei.ContainerID)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"container": ei.ContainerID,
					"error":     err,
				}).Error("failed to find container")
			} else {
				labels, err := ctr.Labels(ctx)
				if err != nil {
					c.logger.WithFields(logrus.Fields{
						"container": ei.ContainerID,
						"error":     err,
					}).Error("failed to get container labels")
					return
				}
				newFIFOSet(labels[DockerContainerBundlePath], ei.ProcessID, true, false).Close()
			}
			_, err = p.Delete(context.Background())
			if err != nil {
				c.logger.WithError(err).WithFields(logrus.Fields{
					"container": ei.ContainerID,
					"process":   ei.ProcessID,
				}).Warn("failed to delete process")
			}
		}
	})
}


func (c *client) processEventStream(ctx context.Context, ns string) {
	var (
		err error
		ev  *events.Envelope
		et  libcontainerdtypes.EventType
		ei  libcontainerdtypes.EventInfo
	)

	// Filter on both namespace *and* topic. To create an "and" filter,
	// this must be a single, comma-separated string
	eventStream, errC := c.client.EventService().Subscribe(ctx, "namespace=="+ns+",topic~=|^/tasks/|")

	c.logger.Debug("processing event stream")

	for {
		var oomKilled bool
		select {
		case err = <-errC:
			if err != nil {
				errStatus, ok := status.FromError(err)
				if !ok || errStatus.Code() != codes.Canceled {
					c.logger.WithError(err).Error("failed to get event")

					// rate limit
					select {
					case <-time.After(time.Second):
						go c.processEventStream(ctx, ns)
						return
					case <-ctx.Done():
					}
				}
				c.logger.WithError(ctx.Err()).Info("stopping event stream following graceful shutdown")
			}
			return
		case ev = <-eventStream:
			if ev.Event == nil {
				c.logger.WithField("event", ev).Warn("invalid event")
				continue
			}

			v, err := typeurl.UnmarshalAny(ev.Event)
			if err != nil {
				c.logger.WithError(err).WithField("event", ev).Warn("failed to unmarshal event")
				continue
			}

			c.logger.WithField("topic", ev.Topic).Debug("event")

			switch t := v.(type) {
			case *apievents.TaskCreate:
				et = libcontainerdtypes.EventCreate
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					ProcessID:   t.ContainerID,
					Pid:         t.Pid,
				}
			case *apievents.TaskStart:
				et = libcontainerdtypes.EventStart
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					ProcessID:   t.ContainerID,
					Pid:         t.Pid,
				}
			case *apievents.TaskExit:

			//there
				et = libcontainerdtypes.EventExit
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					ProcessID:   t.ID,
					Pid:         t.Pid,
					ExitCode:    t.ExitStatus,
					ExitedAt:    t.ExitedAt,
				}
			case *apievents.TaskOOM:
				et = libcontainerdtypes.EventOOM
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					OOMKilled:   true,
				}
				oomKilled = true
			case *apievents.TaskExecAdded:
				et = libcontainerdtypes.EventExecAdded
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					ProcessID:   t.ExecID,
				}
			case *apievents.TaskExecStarted:
				et = libcontainerdtypes.EventExecStarted
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
					ProcessID:   t.ExecID,
					Pid:         t.Pid,
				}
			case *apievents.TaskPaused:
				et = libcontainerdtypes.EventPaused
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
				}
			case *apievents.TaskResumed:
				et = libcontainerdtypes.EventResumed
				ei = libcontainerdtypes.EventInfo{
					ContainerID: t.ContainerID,
				}
			default:
				c.logger.WithFields(logrus.Fields{
					"topic": ev.Topic,
					"type":  reflect.TypeOf(t)},
				).Info("ignoring event")
				continue
			}

			c.oomMu.Lock()
			if oomKilled {
				c.oom[ei.ContainerID] = true
			}
			ei.OOMKilled = c.oom[ei.ContainerID]
			c.oomMu.Unlock()

			c.processEvent(ctx, et, ei)
		}
	}
}


// NewClient creates a new libcontainerd client from a containerd client
func NewClient(ctx context.Context, cli *containerd.Client, stateDir, ns string, b libcontainerdtypes.Backend, useShimV2 bool) (libcontainerdtypes.Client, error) {
	c := &client{
		client:        cli,
		stateDir:      stateDir,
		logger:        logrus.WithField("module", "libcontainerd").WithField("namespace", ns),
		ns:            ns,
		backend:       b,
		oom:           make(map[string]bool),
		useShimV2:     useShimV2,
		v2runcoptions: make(map[string]v2runcoptions.Options),
	}

	go c.processEventStream(ctx, ns)

	return c, nil
}

// NewClient creates a new libcontainerd client from a containerd client
func NewClient(ctx context.Context, cli *containerd.Client, stateDir, ns string, b libcontainerdtypes.Backend, useShimV2 bool) (libcontainerdtypes.Client, error) {
	return remote.NewClient(ctx, cli, stateDir, ns, b, useShimV2)
}