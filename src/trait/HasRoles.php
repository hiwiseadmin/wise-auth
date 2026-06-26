<?php
/**
 * 用户角色关联 Trait
 *
 * 使用此 Trait 的模型将获得完整的 RBAC 权限判断能力。
 * 支持多态关联，适用于不同用户类型（admin, member 等）。
 *
 * 使用方式：
 * ```php
 * class Admin extends Model
 * {
 *     use \wise\auth\trait\HasRoles;
 * }
 * ```
 */
namespace wise\auth\trait;

use think\facade\Event;
use wise\auth\model\Role;
use wise\auth\service\RbacManager;

trait HasRoles
{
    /**
     * 获取当前模型的 user_type 标识
     * 子类可覆盖此方法以返回自定义类型。
     *
     * @return string
     */
    public function getAuthUserType(): string
    {
        // 默认使用类名的小写短名作为 user_type
        $class = get_class($this);
        $parts = explode('\\', $class);
        return strtolower(array_pop($parts));
    }

    /**
     * 需要在模型中自定义用户唯一标识
     */
    // public function getTotpLabel(): string
    // {
        // return $this->username;
    // }
    
    /**
     * 获取用户唯一标识
     *
     * @return int|string
     */
    public function getAuthIdentifier()
    {
        return $this->getKey();
    }

    // =============================
    // 关联
    // =============================

    /**
     * 角色关联（多对多，多态）
     *
     * @return \think\model\relation\MorphToMany
     */
    public function roles()
    {
        $pivotTable = config('wise-auth.table_names.user_role', 'auth_user_role');
        return $this->morphToMany(
            Role::class,
            $pivotTable,
            'user',
            'role_id'
        );
    }

    // =============================
    // 角色操作
    // =============================

    /**
     * 获取所有角色
     *
     * @return \think\Collection
     */
    public function getRoles()
    {
        return $this->roles()->select();
    }

    /**
     * 检查是否拥有指定角色
     *
     * @param string|array $roles      角色 slug 或 slug 数组
     * @param bool         $requireAll 是否必须全部拥有
     * @return bool
     */
    public function hasRole($roles, bool $requireAll = false): bool
    {
        if (is_string($roles)) {
            $roles = [$roles];
        }

        $userRoles = $this->roles()->column('slug');

        if (empty($userRoles)) {
            return false;
        }

        if ($requireAll) {
            return empty(array_diff($roles, $userRoles));
        }

        return !empty(array_intersect($roles, $userRoles));
    }

    /**
     * 将角色 slug 或 ID 统一转换为数字 ID 数组
     *
     * @param array $roleIds 角色 slug 或 ID 的混合数组
     * @return array 角色数字 ID 数组
     */
    private function resolveRoleIds(array $roleIds): array
    {
        $ids = [];
        foreach ($roleIds as $id) {
            if (!is_numeric($id)) {
                $role = Role::where('slug', $id)->find();
                if ($role) {
                    $ids[] = $role->id;
                }
            } else {
                $ids[] = (int)$id;
            }
        }
        return $ids;
    }

    /**
     * 分配角色
     *
     * @param int|string|array $roleIds 角色ID或slug，支持数组
     * @return bool
     */
    public function assignRole($roleIds): bool
    {
        $roleIds = is_array($roleIds) ? $roleIds : [$roleIds];
        $ids = $this->resolveRoleIds($roleIds);
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();

        if (empty($ids)) {
            return false;
        }

        // 约束检查
        $manager = app(RbacManager::class);
        foreach ($ids as $roleId) {
            if (!$manager->checkConstraint('beforeAssignRole', $userId, $userType, $roleId)) {
                return false;
            }
        }

        // 触发分配前事件
        Event::trigger('RbacRoleAssigning', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        $this->roles()->attach($ids);

        // 触发分配后事件
        Event::trigger('RbacRoleAssigned', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        // 清除缓存
        $manager->clearUserCache($userId, $userType);

        return true;
    }

    /**
     * 移除角色
     *
     * @param int|string|array $roleIds
     * @return bool
     */
    public function removeRole($roleIds): bool
    {
        $roleIds = is_array($roleIds) ? $roleIds : [$roleIds];
        $ids = $this->resolveRoleIds($roleIds);
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();

        // 触发移除前事件
        Event::trigger('RbacRoleRemoving', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        $this->roles()->detach($ids);

        // 触发移除后事件
        Event::trigger('RbacRoleRemoved', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        $manager = app(RbacManager::class);
        $manager->clearUserCache($userId, $userType);

        return true;
    }

    /**
     * 同步角色（先移除后分配）
     *
     * @param array $roleIds
     * @return bool
     */
    public function syncRoles(array $roleIds): bool
    {
        $this->roles()->detach();

        if (!empty($roleIds)) {
            $ids = $this->resolveRoleIds($roleIds);
            $this->roles()->attach($ids);
        }
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();
        
        $manager = app(RbacManager::class);
        $manager->clearUserCache($userId, $userType);
        
        Event::trigger('RbacRoleSynced', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $roleIds,
        ]);

        return true;
    }

    // =============================
    // 权限检查
    // =============================

    /**
     * 检查是否拥有指定权限（单个）
     *
     * @param string $permission 权限标识
     * @return bool
     */
    public function can(string $permission): bool
    {
        return $this->hasPermission($permission);
    }

    /**
     * 检查是否拥有指定权限
     *
     * @param string|array $permissions 权限标识或标识数组
     * @param bool         $requireAll 是否必须全部拥有
     * @return bool
     */
    public function hasPermission($permissions, bool $requireAll = false): bool
    {
        // 超级管理员直接通过
        if ($this->isSuperAdmin()) {
            return true;
        }

        if (is_string($permissions)) {
            $permissions = [$permissions];
        }

        // 空权限数组：无权限要求，视为通过
        if (empty($permissions)) {
            return true;
        }

        $userPermissions = $this->getAllPermissions();

        if ($requireAll) {
            return empty(array_diff($permissions, $userPermissions));
        }

        return !empty(array_intersect($permissions, $userPermissions));
    }

    /**
     * 获取用户所有权限标识
     *
     * @return array
     */
    public function getAllPermissions(): array
    {
        // 超级管理员返回特殊标记
        if ($this->isSuperAdmin()) {
            return ['*'];
        }

        $manager = app(RbacManager::class);
        return $manager->getUserPermissions($this->getAuthIdentifier(), $this->getAuthUserType());
    }

    /**
     * 是否为超级管理员
     *
     * @return bool
     */
    public function isSuperAdmin(): bool
    {
        // 检查 super_admin_ids 配置
        $superAdminIds = config('wise-auth.super_admin_ids', []);
        if (in_array($this->getAuthIdentifier(), $superAdminIds)) {
            return true;
        }

        // 检查 super_role 配置
        $superRole = config('wise-auth.super_role');
        if ($superRole && $this->hasRole($superRole)) {
            return true;
        }

        return false;
    }

    // =============================
    // 权限缓存清除
    // =============================

    /**
     * 模型事件：保存/删除后自动清除权限缓存
     *
     * 注意：角色分配/移除/同步操作已在对应方法中显式清除缓存，
     * 此处 saved 事件仅处理新建模型的场景（如分配默认角色后需要刷新）。
     * deleted 事件需要清除，防止已删除用户的缓存残留。
     */
    public static function bootHasRoles(): void
    {
        // static::saved(function ($model) {
        //     // 仅新建时清除缓存（更新操作由 assignRole/removeRole/syncRoles 显式处理）
        //     if ($model->wasRecentlyCreated && method_exists($model, 'getAuthIdentifier') && method_exists($model, 'getAuthUserType')) {
        //         $manager = app(RbacManager::class);
        //         $manager->clearUserCache(
        //             $model->getAuthIdentifier(),
        //             $model->getAuthUserType()
        //         );
        //     }
        // });

        // static::deleted(function ($model) {
        //     if (method_exists($model, 'getAuthIdentifier') && method_exists($model, 'getAuthUserType')) {
        //         $manager = app(RbacManager::class);
        //         $manager->clearUserCache(
        //             $model->getAuthIdentifier(),
        //             $model->getAuthUserType()
        //         );
        //     }
        // });
    }
}
