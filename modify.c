// do_exit函数 /kernel/exit.c      L711  ppid
// cgroup_exit函数 /kernel/cgroup/cgroup.c  L5982
// css_set_move_task  /kernel/cgroup/cgroup.c L878
// cgroup_update_populated 同上 L798

// cgroup_rmdir  /kernel/cgroup/cgroup.c L5520  ppid
//css_clear_dir  /kernel/cgroup/cgroup.c L1647  ppid
//cgroup_rm_file L1626		ppid

//cgroup_file_notify L4088  ppid if

// kernfs_notify  /fs/kernfs/file.c  L931  ppid
//kernfs_notify_workfn /fs/kernfs/file.c L865 ppid


/**
 * Docker源码
 *  /daemon/stop.go
 *  /api/server/server.go serveAPI L86
 *  /api/server/router/container/container_router.go postContainersStop L225
 * \libcontainerd\remote\client.go  	L350
 * 
 **/

/**
 * Containerd源码
 * 			vendor\k8s.io\cri-api\pkg\apis\runtime\v1alpha2\api.pb.go L7822 L5
 * 			_RuntimeService_RemoveContainer_Handler 
 * 			L7407 
 * 			该文件自动生成不能编辑
 * 
 * 			\vendor\github.com\containerd\cri\pkg\server\container_stop.go L38
 * 
 *			 \vendor\github.com\containerd\cri\pkg\server\instrumented_service.go 214
 * kill相关
 * pkg\process\exec.go  L137
 * pkg\process\init.go  L345
 * process.go L134
 * task.go	L191
 * 
 * 
 * docker 中kill相关
 * testutil\daemon\daemon.go  L396
 * vendor\github.com\containerd\containerd\pkg\process\exec.go  L138
 * vendor\github.com\containerd\containerd\pkg\process\init.go  L348
 * vendor\github.com\containerd\containerd\process.go   		L134
 * vendor\github.com\containerd\containerd\runtime\v1\linux\task.go	L217
 * vendor\github.com\containerd\containerd\task.go				L215
 * 
 * containerd kill处理
 * api\services\tasks\v1\tasks.pb.go	L1354
 * runtime\v1\shim\service.go	L371
 * runtime\v1\shim\v1\shim.pb.go L2830
 * runtime\v2\runc\container.go		L404
 * runtime\v2\runc\v1\service.go	L430
 * runtime\v2\runc\v2\service.go	L506
 * runtime\v2\task\shim.pb.go	L3604
 * services\tasks\local.go	L383
 * services\tasks\service.go	L100
 * 
 * local kill(3 args)处理
 * runtime\v1\linux\process.go	L50
 * runtime\v1\linux\task.go	L217
 * runtime\v2\process.go	L39
 * runtime\v2\shim.go	L313
 * 
 * 
 * shim init kill 处理
 * pkg\process\exec_state.go	L74  L125  L180
 * pkg\process\init_state.go	L91  L208  L288  L361  L435
 * 
 * 
 * runningState Kill
 * pkg\process\init.go  L360
 * pkg\process\exec.go	L152
 * 
 * Init Kill
 * vendor\github.com\containerd\go-runc\runc.go	L323
 * vendor\github.com\containerd\go-runc\command_linux.go	L27
 * 
 * runc
 * kill.go 		L47
 * delete.go	L50
 * 
 * kill处理
 * libcontainer\container_linux.go  L381
 * libcontainer\init_linux.go	L475
 * libcontainer\process_linux.go	L508
 * 
 * libcontainer\restored_process.go	L68	L119
 * 
 * delete 查看
 * 
 * dockerd delete路由
 * 
 * containerd delete 时间测量
 * 
 * docker and containerd
 * vendor\github.com\containerd\cgroups\cgroup.go
 * vendor\github.com\containerd\cgroups\cgroup.go
 * 
 * 
 * delete向上追溯
 * vendor\github.com\containerd\containerd\containerstore.go  
 * vendor\github.com\containerd\containerd\content\proxy\content_store.go
 * vendor\github.com\containerd\containerd\image_store.go
 * vendor\github.com\containerd\containerd\leases\proxy\manager.go
 * vendor\github.com\containerd\containerd\task.go
 * 
 * libcontainerd\remote\client.go
 * 
 * 
 * delete与post时间测试
 * daemon\monitor.go
 * client\container_stop.go
 * libcontainerd\libcontainerd_linux.go
 * libcontainerd\remote\client.go
 * 
 * 
 * runc delete
 * hook测试：
 * libcontainer\state_linux.go
 * libcontainer\configs\config.go
 * 
 * dockerd middleware
 * api\server\middleware\cors.go
 * api\server\middleware\experimental.go
 * api\server\middleware\version.go
 * pkg\authorization\middleware.go
 * 
 **/
void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	struct timespec64 time1,time2;

	

	profile_task_exit(tsk);
	kcov_task_exit(tsk);

	WARN_ON(blk_needs_flush_plug(tsk));

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	/*
	 * If do_exit is called because this processes oopsed, it's possible
	 * that get_fs() was left as KERNEL_DS, so reset it to USER_DS before
	 * continuing. Amongst other possible reasons, this is to prevent
	 * mm_release()->clear_child_tid() from writing to a user-controlled
	 * kernel address.
	 */
	set_fs(USER_DS);

	ptrace_event(PTRACE_EVENT_EXIT, code);

	validate_creds_for_do_exit(tsk);

	/*
	 * We're taking recursive faults here in do_exit. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		futex_exit_recursive(tsk);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	exit_signals(tsk);  /* sets PF_EXITING */

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}

	/* sync mm's RSS info before statistics gathering */
	if (tsk->mm)
		sync_mm_rss(tsk->mm);
	acct_update_integrals(tsk);
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk->signal);
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	acct_collect(code, group_dead);
	if (group_dead)
		tty_audit_exit();
	audit_free(tsk);

	tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);

	ktime_get_real_ts64(&time1);

	exit_mm();

	ktime_get_real_ts64(&time2);

	printk("%d: do_exit mm time %lld\n",current->pid, (time2.tv_sec-time1.tv_sec)*1000000000+time2.tv_nsec-time1.tv_nsec );

	if (group_dead)
		acct_process();
	trace_sched_process_exit(tsk);

	exit_sem(tsk);
	exit_shm(tsk);
	exit_files(tsk);
	exit_fs(tsk);
	if (group_dead)
		disassociate_ctty(1);
	exit_task_namespaces(tsk);
	exit_task_work(tsk);
	exit_thread(tsk);
	exit_umh(tsk);

	/*
	 * Flush inherited counters to the parent - before the parent
	 * gets woken up by child-exit notifications.
	 *
	 * because of cgroup mode, must be called before cgroup_exit()
	 */
	perf_event_exit_task(tsk);

	sched_autogroup_exit_task(tsk);

	ktime_get_real_ts64(&time1);

	cgroup_exit(tsk);
	ktime_get_real_ts64(&time2);

	printk("%d: do_exit cgroup time %lld\n",current->pid, (time2.tv_sec-time1.tv_sec)*1000000000+time2.tv_nsec-time1.tv_nsec );


	/*
	 * FIXME: do that only when needed, using sched_exit tracepoint
	 */
	flush_ptrace_hw_breakpoint(tsk);

	exit_tasks_rcu_start();
	exit_notify(tsk, group_dead);
	proc_exit_connector(tsk);
	mpol_put_task_policy(tsk);
#ifdef CONFIG_FUTEX
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#endif
	/*
	 * Make sure we are holding no locks:
	 */
	debug_check_no_locks_held();

	if (tsk->io_context)
		exit_io_context(tsk);

	if (tsk->splice_pipe)
		free_pipe_info(tsk->splice_pipe);

	if (tsk->task_frag.page)
		put_page(tsk->task_frag.page);

	validate_creds_for_do_exit(tsk);

	check_stack_usage();
	preempt_disable();
	if (tsk->nr_dirtied)
		__this_cpu_add(dirty_throttle_leaks, tsk->nr_dirtied);
	exit_rcu();
	exit_tasks_rcu_finish();

	lockdep_free_task(tsk);
	do_task_dead();
}
EXPORT_SYMBOL_GPL(do_exit);


/**
 * cgroup_exit - detach cgroup from exiting task
 * @tsk: pointer to task_struct of exiting process
 *
 * Description: Detach cgroup from @tsk.
 *
 */
void cgroup_exit(struct task_struct *tsk)
{
	struct cgroup_subsys *ss;
	struct css_set *cset;
	int i;

	printk("%d: cgroup_exit 1\n",current->pid);
	//css_set_lock protects task->cgroups pointer, the list of css_set
 	//objects, and the chain of tasks off each css_set. 旋转锁
	spin_lock_irq(&css_set_lock);

	WARN_ON_ONCE(list_empty(&tsk->cg_list));		//cg_list将连到同一个css_set的进程组织成一个链表
	cset = task_css_set(tsk);			//获得tsk->cgroups 指针
	css_set_move_task(tsk, cset, NULL, false);   //tsk从 cset移除
	list_add_tail(&tsk->cg_list, &cset->dying_tasks);	//将第一项加入第二项的前面
	cset->nr_tasks--;		//css_set进程数减一

	printk("%d: cgroup_exit 2\n",current->pid);

	WARN_ON_ONCE(cgroup_task_frozen(tsk));
	if (unlikely(cgroup_task_freeze(tsk)))
		cgroup_update_frozen(task_dfl_cgroup(tsk));

	printk("%d: cgroup_exit 3\n",current->pid);

	spin_unlock_irq(&css_set_lock);

	/* see cgroup_post_fork() for details */
	do_each_subsys_mask(ss, i, have_exit_callback) {
		ss->exit(tsk);
	} while_each_subsys_mask();
	printk("%d: cgroup_exit 4\n",current->pid);
}

static void css_set_move_task(struct task_struct *task,
			      struct css_set *from_cset, struct css_set *to_cset,
			      bool use_mg_tasks)
{
    printk("%d: css_set_move_task\n",current->pid);
	lockdep_assert_held(&css_set_lock);

	if (to_cset && !css_set_populated(to_cset))
		css_set_update_populated(to_cset, true);

	if (from_cset) {
		WARN_ON_ONCE(list_empty(&task->cg_list));

		css_set_skip_task_iters(from_cset, task);
		list_del_init(&task->cg_list);
        printk("%d: css_set_move_task 1\n",current->pid);

		if (!css_set_populated(from_cset))
			css_set_update_populated(from_cset, false);
        printk("%d: css_set_move_task 2\n",current->pid);
	} else {
		WARN_ON_ONCE(!list_empty(&task->cg_list));
	}

	if (to_cset) {
		/*
		 * We are synchronized through cgroup_threadgroup_rwsem
		 * against PF_EXITING setting such that we can't race
		 * against cgroup_exit()/cgroup_free() dropping the css_set.
		 */
		WARN_ON_ONCE(task->flags & PF_EXITING);

		cgroup_move_task(task, to_cset);
		list_add_tail(&task->cg_list, use_mg_tasks ? &to_cset->mg_tasks :
							     &to_cset->tasks);
	}
}

int cgroup_rmdir(struct kernfs_node *kn)
{
	struct cgroup *cgrp;
	int ret = 0;
	printk("%d: cgroup_rmdir\n",current->pid);
	cgrp = cgroup_kn_lock_live(kn, false);
	if (!cgrp)
		return 0;

	ret = cgroup_destroy_locked(cgrp);
	if (!ret)
		TRACE_CGROUP_PATH(rmdir, cgrp);

	cgroup_kn_unlock(kn);
	return ret;
}

static void css_clear_dir(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	struct cftype *cfts;
    printk("pid %d ppid %d: css_clear_dir\n",current->pid,current->reall_parent->pid);
	if (!(css->flags & CSS_VISIBLE))
		return;

	css->flags &= ~CSS_VISIBLE;

	if (!css->ss) {
		if (cgroup_on_dfl(cgrp))
			cfts = cgroup_base_files;
		else
			cfts = cgroup1_base_files;

		cgroup_addrm_files(css, cgrp, cfts, false);
	} else {
		list_for_each_entry(cfts, &css->ss->cfts, node)
			cgroup_addrm_files(css, cgrp, cfts, false);
	}
}


static void cgroup_update_populated(struct cgroup *cgrp, bool populated)
{
	struct cgroup *child = NULL;
	int adj = populated ? 1 : -1;

	lockdep_assert_held(&css_set_lock);

	do {
		printk("%d: cgroup_update_populated\n",current->pid);

		bool was_populated = cgroup_is_populated(cgrp);

		if (!child) {
			cgrp->nr_populated_csets += adj;
		} else {
			if (cgroup_is_threaded(child))
				cgrp->nr_populated_threaded_children += adj;
			else
				cgrp->nr_populated_domain_children += adj;
		}

		if (was_populated == cgroup_is_populated(cgrp))
			break;

		cgroup1_check_for_release(cgrp);
		TRACE_CGROUP_PATH(notify_populated, cgrp,
				  cgroup_is_populated(cgrp));
		cgroup_file_notify(&cgrp->events_file);

		child = cgrp;
		cgrp = cgroup_parent(cgrp);
	} while (cgrp);
}


void cgroup_file_notify(struct cgroup_file *cfile)
{
	unsigned long flags;

    printk("%d: cgroup_file_notify\n",current->pid);

	spin_lock_irqsave(&cgroup_file_kn_lock, flags);
	if (cfile->kn) {
		unsigned long last = cfile->notified_at;
		unsigned long next = last + CGROUP_FILE_NOTIFY_MIN_INTV;

		if (time_in_range(jiffies, last, next)) {
			printk("%d: cgroup_file_notify if\n",current->pid);
			timer_reduce(&cfile->notify_timer, next);
		} else {
			kernfs_notify(cfile->kn);
			cfile->notified_at = jiffies;
		}
	}
	spin_unlock_irqrestore(&cgroup_file_kn_lock, flags);
}

void kernfs_notify(struct kernfs_node *kn)
{
	static DECLARE_WORK(kernfs_notify_work, kernfs_notify_workfn);
	unsigned long flags;
	struct kernfs_open_node *on;

    printk("%d: kernfs_notify input\n",current->pid);

	if (WARN_ON(kernfs_type(kn) != KERNFS_FILE))
		return;

	/* kick poll immediately */
	spin_lock_irqsave(&kernfs_open_node_lock, flags);
	on = kn->attr.open;
	if (on) {
		atomic_inc(&on->event);
		wake_up_interruptible(&on->poll);
	}
	spin_unlock_irqrestore(&kernfs_open_node_lock, flags);

	/* schedule work to kick fsnotify */
	spin_lock_irqsave(&kernfs_notify_lock, flags);
	if (!kn->attr.notify_next) {
		kernfs_get(kn);
		kn->attr.notify_next = kernfs_notify_list;
		kernfs_notify_list = kn;
        printk("%d: kernfs_notify schedule\n",current->pid);
		schedule_work(&kernfs_notify_work);
	}
	spin_unlock_irqrestore(&kernfs_notify_lock, flags);
}

static void kernfs_notify_workfn(struct work_struct *work)
{
	struct kernfs_node *kn;
	struct kernfs_super_info *info;
repeat:
     printk("%d: kernfs_notify_workfn\n",current->pid);
	/* pop one off the notify_list */
	spin_lock_irq(&kernfs_notify_lock);
	kn = kernfs_notify_list;
	if (kn == KERNFS_NOTIFY_EOL) {
		spin_unlock_irq(&kernfs_notify_lock);
		return;
	}
	kernfs_notify_list = kn->attr.notify_next;
	kn->attr.notify_next = NULL;
	spin_unlock_irq(&kernfs_notify_lock);

	/* kick fsnotify */
	mutex_lock(&kernfs_mutex);

	list_for_each_entry(info, &kernfs_root(kn)->supers, node) {
		struct kernfs_node *parent;
		struct inode *inode;
		struct qstr name;

		/*
		 * We want fsnotify_modify() on @kn but as the
		 * modifications aren't originating from userland don't
		 * have the matching @file available.  Look up the inodes
		 * and generate the events manually.
		 */
		inode = ilookup(info->sb, kernfs_ino(kn));
		if (!inode)
			continue;

		name = (struct qstr)QSTR_INIT(kn->name, strlen(kn->name));
		parent = kernfs_get_parent(kn);
		if (parent) {
			struct inode *p_inode;

			p_inode = ilookup(info->sb, kernfs_ino(parent));
			if (p_inode) {
				fsnotify(p_inode, FS_MODIFY | FS_EVENT_ON_CHILD,
					 inode, FSNOTIFY_EVENT_INODE, &name, 0);
				iput(p_inode);
			}

			kernfs_put(parent);
		}

		fsnotify(inode, FS_MODIFY, inode, FSNOTIFY_EVENT_INODE,
			 &name, 0);
		iput(inode);
	}

	mutex_unlock(&kernfs_mutex);
	kernfs_put(kn);
	goto repeat;
}
