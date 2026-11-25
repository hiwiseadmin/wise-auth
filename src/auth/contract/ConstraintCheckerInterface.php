<?php
/**
 * RBAC2 约束检查器接口
 *
 * 实现此接口以注入自定义约束检查逻辑（如互斥角色、基数限制等）。
 */
namespace wise\auth\contract;

interface ConstraintCheckerInterface
{
    /**
     * 角色分配前检查
     *
     * @param int|string  $userId    用户 ID
     * @param string      $userType  用户类型
     * @param int|string  $roleId    待分配角色 ID
     * @param array       $context   上下文（包含现有角色信息等）
     * @return bool 返回 false 表示阻止分配
     * @throws \wise\auth\exception\ConstraintViolationException
     */
    public function checkBeforeAssignRole(int|string $userId, string $userType, int|string $roleId, array $context = []): bool;

    /**
     * 权限赋予前检查
     *
     * @param int|string $roleId       角色 ID
     * @param int|string $permissionId 权限 ID
     * @param array      $context      上下文
     * @return bool
     * @throws \wise\auth\exception\ConstraintViolationException
     */
    public function checkBeforeGrantPermission(int|string $roleId, int|string $permissionId, array $context = []): bool;

    /**
     * 角色创建/更新前检查
     *
     * @param array $data 角色数据
     * @param int|string|null $roleId 更新时的角色ID，创建时为 null
     * @return bool
     * @throws \wise\auth\exception\ConstraintViolationException
     */
    public function checkBeforeSaveRole(array $data, int|string|null $roleId = null): bool;
}
