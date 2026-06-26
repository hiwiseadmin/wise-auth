<?php
/**
 * 用户模型契约接口
 *
 * 任何需要接入 WiseAuth 的用户模型都应实现此接口。
 * 配合 HasRoles Trait 使用可快速满足所有要求。
 */
namespace wise\auth\contract;

interface UserContract
{
    /**
     * 获取用户唯一标识
     *
     * @return int|string
     */
    public function getAuthIdentifier();

    /**
     * 获取用户类型标识（用于多态关联）
     * 如 'admin', 'member' 等
     *
     * @return string
     */
    public function getAuthUserType(): string;

    /**
     * 获取用户拥有的所有角色
     *
     * @return \think\Collection
     */
    public function getRoles();

    /**
     * 检查用户是否拥有指定角色
     *
     * @param string|array $roles 角色 slug 或 slug 数组
     * @param bool         $requireAll 是否必须拥有全部角色
     * @return bool
     */
    public function hasRole($roles, bool $requireAll = false): bool;

    /**
     * 检查用户是否拥有指定权限
     *
     * @param string|array $permissions 权限标识或标识数组
     * @param bool         $requireAll 是否必须拥有全部权限
     * @return bool
     */
    public function hasPermission($permissions, bool $requireAll = false): bool;

    /**
     * 检查用户是否拥有指定权限（can 别名）
     *
     * @param string $permission
     * @return bool
     */
    public function can(string $permission): bool;

    /**
     * 获取用户所有权限标识
     *
     * @return array
     */
    public function getAllPermissions(): array;

    /**
     * 是否为超级管理员
     *
     * @return bool
     */
    public function isSuperAdmin(): bool;

    /**
     * 分配角色
     *
     * @param int|string|array $roleIds
     * @return bool
     */
    public function assignRole($roleIds): bool;

    /**
     * 移除角色
     *
     * @param int|string|array $roleIds
     * @return bool
     */
    public function removeRole($roleIds): bool;

    /**
     * 同步角色（先移除所有现有角色，再分配新角色）
     *
     * @param array $roleIds
     * @return bool
     */
    public function syncRoles(array $roleIds): bool;
}
