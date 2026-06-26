<?php
/**
 * WiseAuth 事件订阅者
 *
 * 自动监听角色和权限模型的变化，触发缓存清除等操作。
 */
namespace wise\auth\subscribe;

use think\facade\Event;
use wise\auth\event\RoleChanged;
use wise\auth\event\PermissionChanged;
use wise\auth\service\RbacManager;
use wise\auth\service\PermissionRegistrar;

class AuthEventSubscriber
{
    /**
     * 订阅事件
     *
     * @param \think\Event $event
     */
    public function subscribe($event): void
    {
        // 角色事件
        $event->listen(RoleChanged::class, [$this, 'onRoleChanged']);

        // 权限事件
        $event->listen(PermissionChanged::class, [$this, 'onPermissionChanged']);

        // RBAC 角色分配事件
        $event->listen('RbacRoleAssigning', [$this, 'onRoleAssigning']);
        $event->listen('RbacRoleAssigned', [$this, 'onRoleAssigned']);
        $event->listen('RbacRoleRemoving', [$this, 'onRoleRemoving']);
        $event->listen('RbacRoleRemoved', [$this, 'onRoleRemoved']);
    }

    /**
     * 角色变更处理
     *
     * @param RoleChanged $event
     */
    public function onRoleChanged(RoleChanged $event): void
    {
        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);

        // 清除该角色关联的所有用户缓存
        $manager->clearRoleCache($event->roleId);

        // 如果是更新或删除，也要清除相关角色缓存
        if (in_array($event->action, ['update', 'delete'])) {
            $manager->clearAllCache();
        }
    }

    /**
     * 权限变更处理
     *
     * @param PermissionChanged $event
     */
    public function onPermissionChanged(PermissionChanged $event): void
    {
        /** @var PermissionRegistrar $registrar */
        $registrar = app(PermissionRegistrar::class);
        $registrar->clearPermissionsCache();

        // 清除所有用户权限缓存
        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);
        $manager->clearAllCache();
    }

    /**
     * 角色分配前
     *
     * @param array $data
     */
    public function onRoleAssigning(array $data): void
    {
        // 预留：可用于日志记录、额外校验等
    }

    /**
     * 角色分配后
     *
     * @param array $data
     */
    public function onRoleAssigned(array $data): void
    {
        // 清除用户缓存
        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);
        $manager->clearUserCache(
            $data['user_id'] ?? 0,
            $data['user_type'] ?? 'admin'
        );
    }

    /**
     * 角色移除前
     *
     * @param array $data
     */
    public function onRoleRemoving(array $data): void
    {
        // 预留
    }

    /**
     * 角色移除后
     *
     * @param array $data
     */
    public function onRoleRemoved(array $data): void
    {
        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);
        $manager->clearUserCache(
            $data['user_id'] ?? 0,
            $data['user_type'] ?? 'admin'
        );
    }
}
