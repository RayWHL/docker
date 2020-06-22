/**
 * stop cli端代码 /client/container_stop.go
 *      post请求到daemon端
 * daemon端代码  /daemon/stop.go
 * 
 * 
 * 查看daemon日志  journalctl -r -u docker.service
 * 
 * 
 * /daemon/stop.go L35 加日志
 * \api\server\router\container\container_routes.go L225 加日志
 * 
 * */

/**
 * kernfs_iop_rmdir 调用 cgroup_root 中的kernfs的rmdir
 * 引用op->rmdir : vfs_rmdir xattr_rmdir
