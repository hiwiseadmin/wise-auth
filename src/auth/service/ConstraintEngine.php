<?php
/**
 * RBAC2 约束检查引擎
 *
 * 从 RbacManager 中拆分出的独立约束检查服务，
 * 负责所有 RBAC2 内置约束（互斥角色、基数限制、前置角色、层级/子节点限制）的校验。
 *
 * 职责单一：只做约束检查，不涉及缓存、路由匹配等其他逻辑。
 */
namespace wise\auth\service;

use wise\auth\model\Role;
use wise\auth\model\UserRole;
use wise\auth\exception\ConstraintViolationException;

class ConstraintEngine
{
    /**
     * 执行约束检查（统一入口）
     *
     * @param string $method    检查方法名（beforeAssignRole / checkBeforeSaveRole 等）
     * @param mixed  ...$args   参数
     * @return bool
     * @throws ConstraintViolationException
     */
    public function checkConstraint(string $method, ...$args): bool
    {
        $checker = config('wise-auth.constraint_checker');
        if ($checker) {
            $candidates = [$method];
            if (stripos($method, 'check') !== 0) {
                $candidates[] = 'check' . ucfirst($method);
            }

            if ($checker instanceof \Closure) {
                return $checker($method, ['args' => $args]);
            }
            if (class_exists($checker)) {
                $instance = new $checker();
                foreach ($candidates as $candidate) {
                    if (method_exists($instance, $candidate)) {
                        return $instance->$candidate(...$args);
                    }
                }
            }
        }

        return $this->checkBuiltinConstraints($method, ...$args);
    }

    /**
     * 内置约束规则检查
     *
     * @param string $method
     * @param mixed  ...$args
     * @return bool
     * @throws ConstraintViolationException
     */
    public function checkBuiltinConstraints(string $method, ...$args): bool
    {
        $constraints = config('wise-auth.constraints', []);

        switch ($method) {
            case 'beforeAssignRole':
                if (!isset($args[0], $args[1], $args[2])) {
                    return true;
                }
                $this->checkMutualExclusion($args[0], $args[1], $args[2]);
                $this->checkCardinality($args[0], $args[1], $args[2]);
                $this->checkPrerequisite($args[0], $args[1], $args[2], $constraints);
                return true;

            case 'checkBeforeSaveRole':
                return $this->checkSaveRoleConstraints($constraints, ...$args);

            default:
                return true;
        }
    }

    /**
     * 检查互斥角色
     */
    public function checkMutualExclusion($userId, string $userType, $newRoleId): bool
    {
        $newRole = Role::find($newRoleId);
        if (!$newRole) {
            return true;
        }

        $newRoleSlug = $newRole->slug;

        $existingRoleIds = UserRole::where('user_id', $userId)
            ->where('user_type', $userType)
            ->column('role_id');

        $existingRoleModels = [];
        if (!empty($existingRoleIds)) {
            $existingRoleModels = Role::whereIn('id', $existingRoleIds)->select();
        }

        $existingSlugs = [];
        foreach ($existingRoleModels as $existing) {
            $existingSlugs[] = $existing->slug;
        }

        $newMutex = $this->parseMutex($newRole);
        if (!empty($newMutex)) {
            $intersection = array_intersect($newMutex, $existingSlugs);
            if (!empty($intersection)) {
                throw new ConstraintViolationException(
                    "角色 '{$newRoleSlug}' 与已有角色 '" . implode("', '", $intersection) . "' 互斥，不能同时分配",
                    'mutual_exclusion'
                );
            }
        }

        foreach ($existingRoleModels as $existing) {
            $existingMutex = $this->parseMutex($existing);
            if (in_array($newRoleSlug, $existingMutex, true)) {
                throw new ConstraintViolationException(
                    "角色 '{$newRoleSlug}' 与已有角色 '{$existing->slug}' 互斥，不能同时分配",
                    'mutual_exclusion'
                );
            }
        }

        return true;
    }

    /**
     * 检查角色基数限制
     */
    public function checkCardinality($userId, string $userType, $newRoleId): bool
    {
        $newRole = Role::find($newRoleId);
        if (!$newRole) {
            return true;
        }

        $newRoleSlug = $newRole->slug;

        $maxCount = (int) $newRole->max_members;

        if ($maxCount <= 0) {
            return true;
        }

        $userRoleTable = 'auth_user_role';

        $currentCount = \think\facade\Db::name($userRoleTable)
            ->where('role_id', $newRoleId)
            ->where(function ($query) {
                $this->addExpiredFilter($query);
            })
            ->count();

        if ($this->userHasRole($userId, $userType, $newRoleId)) {
            $currentCount = max(0, $currentCount - 1);
        }

        if ($currentCount >= $maxCount) {
            throw new ConstraintViolationException(
                "角色 '{$newRoleSlug}' 已达到最大分配数量限制（{$maxCount} 人，当前已有 {$currentCount} 人）",
                'cardinality'
            );
        }

        return true;
    }

    /**
     * 检查前置角色
     */
    public function checkPrerequisite($userId, string $userType, $newRoleId, array $constraints): bool
    {
        if (empty($constraints['prerequisite'])) {
            return true;
        }

        $newRole = Role::find($newRoleId);
        if (!$newRole) {
            return true;
        }

        $newRoleSlug = $newRole->slug;

        if (!isset($constraints['prerequisite'][$newRoleSlug])) {
            return true;
        }

        $prerequisiteSlugs = (array) $constraints['prerequisite'][$newRoleSlug];
        if (empty($prerequisiteSlugs)) {
            return true;
        }

        $existingRoleIds = UserRole::where('user_id', $userId)
            ->where('user_type', $userType)
            ->where(function ($query) {
                $this->addExpiredFilter($query);
            })
            ->column('role_id');

        $existingSlugs = [];
        if (!empty($existingRoleIds)) {
            $existingSlugs = Role::whereIn('id', $existingRoleIds)->column('slug');
        }

        $missing = array_diff($prerequisiteSlugs, $existingSlugs);
        if (!empty($missing)) {
            throw new ConstraintViolationException(
                "分配角色 '{$newRoleSlug}' 需要先拥有以下前置角色：'" . implode("', '", $missing) . "'",
                'prerequisite'
            );
        }

        return true;
    }

    /**
     * 检查用户是否已拥有指定角色（仅未过期）
     */
    public function userHasRole($userId, string $userType, $roleId): bool
    {
        $userRoleTable = 'auth_user_role';
        return \think\facade\Db::name($userRoleTable)
            ->where('user_id', $userId)
            ->where('user_type', $userType)
            ->where('role_id', (int) $roleId)
            ->where(function ($query) {
                $this->addExpiredFilter($query);
            })
            ->count() > 0;
    }

    /**
     * 角色保存前的约束检查
     */
    public function checkSaveRoleConstraints(array $constraints, ...$args): bool
    {
        if (!empty($constraints['max_role_depth'])) {
            $maxDepth = (int) $constraints['max_role_depth'];
            $roleData = $args[0] ?? null;
            if (is_array($roleData) && isset($roleData['parent_id']) && $roleData['parent_id'] > 0) {
                $parent = Role::find($roleData['parent_id']);
                if ($parent && ($parent->level ?? 0) >= $maxDepth) {
                    throw new ConstraintViolationException(
                        "角色层级不能超过最大深度限制（{$maxDepth} 层）",
                        'max_role_depth'
                    );
                }
            }
        }

        if (!empty($constraints['max_children'])) {
            $maxChildren = (int) $constraints['max_children'];
            $roleData = $args[0] ?? null;
            if (is_array($roleData) && isset($roleData['parent_id'])) {
                $childrenCount = Role::where('parent_id', $roleData['parent_id'])->count();
                if ($childrenCount >= $maxChildren) {
                    throw new ConstraintViolationException(
                        "父角色下的子角色数量已达到最大限制（{$maxChildren} 个）",
                        'max_children'
                    );
                }
            }
        }

        return true;
    }

    /**
     * 通用过期时间过滤条件
     */
    private function addExpiredFilter($query): void
    {
        $query->whereNull('expired_at')
              ->whereOr('expired_at', '>', date('Y-m-d H:i:s'));
    }

    /**
     * 解析角色的互斥角色标识列表（字段驱动）
     *
     * 兼容模型 JSON 类型转换后的数组、数据库中的 JSON 字符串、
     * 逗号分隔字符串等多种形态，统一返回 slug 字符串数组。
     *
     * @param Role $role
     * @return array
     */
    private function parseMutex(Role $role): array
    {
        $mutex = $role->mutex;

        if (is_array($mutex)) {
            return array_values(array_filter(array_map('strval', $mutex)));
        }

        if (is_string($mutex) && $mutex !== '') {
            $decoded = json_decode($mutex, true);
            if (is_array($decoded)) {
                return array_values(array_filter(array_map('strval', $decoded)));
            }
            return array_values(array_filter(array_map('trim', explode(',', $mutex))));
        }

        return [];
    }
}
