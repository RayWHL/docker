//printk("%d: not same cgroup\n",current->pid);

/**
 * 
 * /kernel/exit.c
 * cgroup_update_populated  /kernel/cgroup/cgroup.c
 * cgroup1_check_for_release  /kernel/cgroup/cgroupv1.c
 * cgroup_rmdir 
 * 
 **/

/*
 * A css_set is a structure holding pointers to a set of
 * cgroup_subsys_state objects. This saves space in the task struct
 * object and speeds up fork()/exit(), since a single inc/dec and a
 * list_add()/del() can bump the reference count on the entire cgroup
 * set for a task.
 */
struct css_set {
	/*
	 * Set of subsystem states, one for each subsystem. This array is
	 * immutable after creation apart from the init_css_set during
	 * subsystem registration (at boot time).
	 */
	struct cgroup_subsys_state *subsys[CGROUP_SUBSYS_COUNT];

	/* reference count */
	refcount_t refcount;

	/*
	 * For a domain cgroup, the following points to self.  If threaded,
	 * to the matching cset of the nearest domain ancestor.  The
	 * dom_cset provides access to the domain cgroup and its csses to
	 * which domain level resource consumptions should be charged.
	 */
	struct css_set *dom_cset;

	/* the default cgroup associated with this css_set */
	struct cgroup *dfl_cgrp;

	/* internal task count, protected by css_set_lock */
	int nr_tasks;

	/*
	 * Lists running through all tasks using this cgroup group.
	 * mg_tasks lists tasks which belong to this cset but are in the
	 * process of being migrated out or in.  Protected by
	 * css_set_rwsem, but, during migration, once tasks are moved to
	 * mg_tasks, it can be read safely while holding cgroup_mutex.
	 */
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;

	/* all css_task_iters currently walking this cset */
	struct list_head task_iters;

	/*
	 * On the default hierarhcy, ->subsys[ssid] may point to a css
	 * attached to an ancestor instead of the cgroup this css_set is
	 * associated with.  The following node is anchored at
	 * ->subsys[ssid]->cgroup->e_csets[ssid] and provides a way to
	 * iterate through all css's attached to a given cgroup.
	 */
	struct list_head e_cset_node[CGROUP_SUBSYS_COUNT];

	/* all threaded csets whose ->dom_cset points to this cset */
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;

	/*
	 * List running through all cgroup groups in the same hash
	 * slot. Protected by css_set_lock
	 */
	struct hlist_node hlist;

	/*
	 * List of cgrp_cset_links pointing at cgroups referenced from this
	 * css_set.  Protected by css_set_lock.
	 */
	struct list_head cgrp_links;

	/*
	 * List of csets participating in the on-going migration either as
	 * source or destination.  Protected by cgroup_mutex.
	 */
	struct list_head mg_preload_node;
	struct list_head mg_node;

	/*
	 * If this cset is acting as the source of migration the following
	 * two fields are set.  mg_src_cgrp and mg_dst_cgrp are
	 * respectively the source and destination cgroups of the on-going
	 * migration.  mg_dst_cset is the destination cset the target tasks
	 * on this cset should be migrated to.  Protected by cgroup_mutex.
	 */
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;

	/* dead and being drained, ignore for migration */
	bool dead;

	/* For RCU-protected deletion */
	struct rcu_head rcu_head;
};


const struct inode_operations kernfs_dir_iops = {
	.lookup		= kernfs_iop_lookup,
	.permission	= kernfs_iop_permission,
	.setattr	= kernfs_iop_setattr,
	.getattr	= kernfs_iop_getattr,
	.listxattr	= kernfs_iop_listxattr,

	.mkdir		= kernfs_iop_mkdir,
	.rmdir		= kernfs_iop_rmdir,
	.rename		= kernfs_iop_rename,
};

struct kernfs_syscall_ops cgroup1_kf_syscall_ops = {
	.rename			= cgroup1_rename,
	.show_options		= cgroup1_show_options,
	.mkdir			= cgroup_mkdir,
	.rmdir			= cgroup_rmdir,
	.show_path		= cgroup_show_path,
};

static struct kernfs_syscall_ops cgroup_kf_syscall_ops = {
	.show_options		= cgroup_show_options,
	.mkdir			= cgroup_mkdir,
	.rmdir			= cgroup_rmdir,
	.show_path		= cgroup_show_path,
};

/*
 * this kills every thread in the thread group. Note that any externally
 * wait4()-ing process will get the correct exit code - even if this
 * thread is not the thread group leader.
 */
SYSCALL_DEFINE1(exit_group, int, error_code)
{
	do_group_exit((error_code & 0xff) << 8);
	/* NOTREACHED */
	return 0;
}

do_group_exit(int exit_code)
{
	struct signal_struct *sig = current->signal;

	BUG_ON(exit_code & 0x80); /* core dumps don't get here */

	if (signal_group_exit(sig))
		exit_code = sig->group_exit_code;
	else if (!thread_group_empty(current)) {
		struct sighand_struct *const sighand = current->sighand;

		spin_lock_irq(&sighand->siglock);
		if (signal_group_exit(sig))
			/* Another thread got here before we took the lock.  */
			exit_code = sig->group_exit_code;
		else {
			sig->group_exit_code = exit_code;
			sig->flags = SIGNAL_GROUP_EXIT;
			zap_other_threads(current);
		}
		spin_unlock_irq(&sighand->siglock);
	}

	do_exit(exit_code);
	/* NOTREACHED */
}


void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

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
		/*
		 * If the last thread of global init has exited, panic
		 * immediately to get a useable coredump.
		 */
		if (unlikely(is_global_init(tsk)))
			panic("Attempted to kill init! exitcode=0x%08x\n",
				tsk->signal->group_exit_code ?: (int)code);

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

	exit_mm();

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
	cgroup_exit(tsk);

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


/**
 * css_set_move_task - move a task from one css_set to another
 * @task: task being moved
 * @from_cset: css_set @task currently belongs to (may be NULL)
 * @to_cset: new css_set @task is being moved to (may be NULL)
 * @use_mg_tasks: move to @to_cset->mg_tasks instead of ->tasks
 *
 * Move @task from @from_cset to @to_cset.  If @task didn't belong to any
 * css_set, @from_cset can be NULL.  If @task is being disassociated
 * instead of moved, @to_cset can be NULL.
 *
 * This function automatically handles populated counter updates and
 * css_task_iter adjustments but the caller is responsible for managing
 * @from_cset and @to_cset's reference counts.
 */
static void css_set_move_task(struct task_struct *task,
			      struct css_set *from_cset, struct css_set *to_cset,
			      bool use_mg_tasks)
{
	lockdep_assert_held(&css_set_lock);

	if (to_cset && !css_set_populated(to_cset))
		css_set_update_populated(to_cset, true);

	if (from_cset) {
		WARN_ON_ONCE(list_empty(&task->cg_list));

		css_set_skip_task_iters(from_cset, task);
		list_del_init(&task->cg_list);		//从cg_list移除
		if (!css_set_populated(from_cset))
			css_set_update_populated(from_cset, false);
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


/**
 * cgroup_update_populated - update the populated count of a cgroup
 * @cgrp: the target cgroup
 * @populated: inc or dec populated count
 *
 * One of the css_sets associated with @cgrp is either getting its first
 * task or losing the last.  Update @cgrp->nr_populated_* accordingly.  The
 * count is propagated towards root so that a given cgroup's
 * nr_populated_children is zero iff none of its descendants contain any
 * tasks.
 *
 * @cgrp's interface file "cgroup.populated" is zero if both
 * @cgrp->nr_populated_csets and @cgrp->nr_populated_children are zero and
 * 1 otherwise.  When the sum changes from or to zero, userland is notified
 * that the content of the interface file has changed.  This can be used to
 * detect when @cgrp and its descendants become populated or empty.
 */
static void cgroup_update_populated(struct cgroup *cgrp, bool populated)
{
	struct cgroup *child = NULL;
	int adj = populated ? 1 : -1;

	lockdep_assert_held(&css_set_lock);

	do {
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

/* no synchronization, the result can only be used as a hint */
static inline bool cgroup_is_populated(struct cgroup *cgrp)
{
	return cgrp->nr_populated_csets + cgrp->nr_populated_domain_children +
		cgrp->nr_populated_threaded_children;
}

void cgroup1_check_for_release(struct cgroup *cgrp)
{
	if (notify_on_release(cgrp) && !cgroup_is_populated(cgrp) &&
	    !css_has_online_children(&cgrp->self) && !cgroup_is_dead(cgrp))
		//没有执行到这？？？
		schedule_work(&cgrp->release_agent_work); //一个工作队列，就是调度一个注册好的函数，大概用于释放cgroup
		//指向cgroup1_release_agent
}



/*
 * Turn us into a lazy TLB process if we
 * aren't already..
 */
static void exit_mm(void)
{
	struct mm_struct *mm = current->mm;
	struct core_state *core_state;

	exit_mm_release(current, mm);
	if (!mm)
		return;
	sync_mm_rss(mm);
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold mmap_sem around checking core_state
	 * and clearing tsk->mm.  The core-inducing thread
	 * will increment ->nr_threads for each thread in the
	 * group with ->mm != NULL.
	 */
	down_read(&mm->mmap_sem);
	core_state = mm->core_state;
	if (core_state) {
		struct core_thread self;

		up_read(&mm->mmap_sem);

		self.task = current;
		self.next = xchg(&core_state->dumper.next, &self);
		/*
		 * Implies mb(), the result of xchg() must be visible
		 * to core_state->dumper.
		 */
		if (atomic_dec_and_test(&core_state->nr_threads))
			complete(&core_state->startup);

		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!self.task) /* see coredump_finish() */
				break;
			freezable_schedule();
		}
		__set_current_state(TASK_RUNNING);
		down_read(&mm->mmap_sem);
	}
	mmgrab(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	current->mm = NULL;
	up_read(&mm->mmap_sem);
	enter_lazy_tlb(mm, current);
	task_unlock(current);
	mm_update_next_owner(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		exit_oom_victim();
}

void exit_mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	futex_exit_release(tsk);
	mm_release(tsk, mm);
}

static void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	uprobe_free_utask(tsk);

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	/*
	 * Signal userspace if we're not exiting with a core dump
	 * because we want to leave the value intact for debugging
	 * purposes.
	 */
	if (tsk->clear_child_tid) {
		if (!(tsk->signal->flags & SIGNAL_GROUP_COREDUMP) &&
		    atomic_read(&mm->mm_users) > 1) {
			/*
			 * We don't check the error code - if userspace has
			 * not set up a proper pointer then tough luck.
			 */
			put_user(0, tsk->clear_child_tid);
			do_futex(tsk->clear_child_tid, FUTEX_WAKE,
					1, NULL, NULL, 0, 0);
		}
		tsk->clear_child_tid = NULL;
	}
    /*
	 * All done, finally we can wake up parent and return this mm to him.
	 * Also kthread_stop() uses this completion for synchronization.
	 */
	if (tsk->vfork_done)
		complete_vfork_done(tsk);
}


/**
 * kernfs_notify - notify a kernfs file
 * @kn: file to notify
 *
 * Notify @kn such that poll(2) on @kn wakes up.  Maybe be called from any
 * context.
 */
void kernfs_notify(struct kernfs_node *kn)
{
	static DECLARE_WORK(kernfs_notify_work, kernfs_notify_workfn);
	unsigned long flags;
	struct kernfs_open_node *on;

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
		schedule_work(&kernfs_notify_work);
	}
	spin_unlock_irqrestore(&kernfs_notify_lock, flags);
}
EXPORT_SYMBOL_GPL(kernfs_notify);


static void kernfs_notify_workfn(struct work_struct *work)
{
	struct kernfs_node *kn;
	struct kernfs_super_info *info;
repeat:
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


