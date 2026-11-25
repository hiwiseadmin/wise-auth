<?php
/**
 * WiseAuth 事件订阅者
 *
 * 自动监听角色和权限模型的变化，触发缓存清除和审计日志。
 */
namespace wise\auth\subscribe;

use wise\support\context\ContextualLogger;
use wise\auth\event\RoleChanged;
use wise\auth\event\PermissionChanged;
use wise\auth\model\AuthAuditLog;
use wise\auth\service\RbacManager;
use wise\auth\service\PermissionRegistrar;

class AuthEventSubscriber
{
    /**
     * 订阅事件
     *
     * @param \think\Event $event
     */
    public function subscribe(\think\Event $event): void
    {
        $event->listen(RoleChanged::class, [$this, 'onRoleChanged']);

        $event->listen(PermissionChanged::class, [$this, 'onPermissionChanged']);

        $event->listen('RbacRoleAssigning', [$this, 'onRoleAssigning']);
        $event->listen('RbacRoleAssigned', [$this, 'onRoleAssigned']);
        $event->listen('RbacRoleRemoving', [$this, 'onRoleRemoving']);
        $event->listen('RbacRoleRemoved', [$this, 'onRoleRemoved']);
    }

    /**
     * 角色变更处理
     */
    public function onRoleChanged(RoleChanged $event): void
    {
        $manager = app(RbacManager::class);

        $manager->clearRoleCache($event->roleId);

        if (in_array($event->action, ['update', 'delete'])) {
            $manager->clearAllCache();
        }

        $this->writeAuditLog(
            'role_' . $event->action,
            'role',
            (int) $event->roleId,
            is_array($event->data) ? $event->data : []
        );
    }

    /**
     * 权限变更处理
     */
    public function onPermissionChanged(PermissionChanged $event): void
    {
        $registrar = app(PermissionRegistrar::class);
        $registrar->clearPermissionsCache();

        $manager = app(RbacManager::class);
        $manager->clearAllCache();

        $this->writeAuditLog(
            'permission_' . $event->action,
            'permission',
            (int) $event->permissionId,
            is_array($event->data) ? $event->data : []
        );
    }

    /**
     * 角色分配前
     */
    public function onRoleAssigning(array $data): void
    {
    }

    /**
     * 角色分配后
     */
    public function onRoleAssigned(array $data): void
    {
        if (empty($data['user_id'])) {
            return;
        }
        $manager = app(RbacManager::class);
        $manager->clearUserCache($data['user_id'], $data['user_type'] ?? 'admin');

        $this->writeAuditLog('role_assigned', 'user_role', (int) ($data['user_id'] ?? 0), [
            'role_ids'   => $data['role_ids'] ?? [],
            'user_type'  => $data['user_type'] ?? 'admin',
            'expired_at' => $data['expired_at'] ?? null,
        ]);
    }

    /**
     * 角色移除前
     */
    public function onRoleRemoving(array $data): void
    {
    }

    /**
     * 角色移除后
     */
    public function onRoleRemoved(array $data): void
    {
        if (empty($data['user_id'])) {
            return;
        }
        $manager = app(RbacManager::class);
        $manager->clearUserCache($data['user_id'], $data['user_type'] ?? 'admin');

        $this->writeAuditLog('role_removed', 'user_role', (int) ($data['user_id'] ?? 0), [
            'role_ids'  => $data['role_ids'] ?? [],
            'user_type' => $data['user_type'] ?? 'admin',
        ]);
    }

    /**
     * 写入审计日志
     *
     * @param string $action     操作类型
     * @param string $entityType 实体类型（role/permission/user_role）
     * @param int    $entityId   实体ID
     * @param array  $detail     操作详情
     */
    protected function writeAuditLog(string $action, string $entityType, int $entityId, array $detail = []): void
    {
        if (!config('wise-auth.audit_enabled', true)) {
            return;
        }

        try {
            AuthAuditLog::create([
                'action'      => $action,
                'entity_type' => $entityType,
                'entity_id'   => $entityId,
                'detail'      => json_encode($detail, JSON_UNESCAPED_UNICODE),
                'operator_id' => $this->getCurrentOperator(),
                'ip'          => request()->ip() ?? '',
                'create_time' => date('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable $e) {
            ContextualLogger::warning("WiseAuth audit log write failed: {$e->getMessage()}");
        }
    }

    /**
     * 获取当前操作者 ID
     *
     * @return int
     */
    protected function getCurrentOperator(): int
    {
        if (PHP_SAPI === 'cli') {
            return 0;
        }

        return (int) (function_exists('auth_id') ? (auth_id('admin') ?? 0) : (session('admin_id') ?? 0));
    }
}
