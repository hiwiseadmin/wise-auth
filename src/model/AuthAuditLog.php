<?php
/**
 * 权限审计日志模型
 *
 * 记录角色分配/移除、权限赋予/撤销等所有 RBAC 变更操作。
 */
namespace wise\auth\model;

use think\Model;

class AuthAuditLog extends Model
{
    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = false;

    protected $name = 'auth_audit_log';
}
