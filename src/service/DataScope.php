<?php
/**
 * 行级数据权限服务（DataScope）
 *
 * 根据用户-角色关联的 data_scope JSON 字段，
 * 自动为查询构建 WHERE 条件实现行级数据过滤。
 *
 * 支持的 data_scope 格式：
 *   {"dept_ids": [1,2,3]}       — 部门数据范围
 *   {"self_only": true}          — 仅自己
 *   {"org_id": 5}                — 指定组织
 *   {"custom": {"field": "value"}} — 自定义条件
 *
 * 使用示例：
 *   $scope = app(DataScope::class);
 *   $query = $scope->apply($query, $user, 'admin.user.list', 'user_id');
 */
namespace wise\auth\service;

use think\db\Query;
use wise\auth\model\UserRole;

class DataScope
{
    /**
     * 应用数据权限过滤
     *
     * @param Query|\think\db\BaseQuery $query      数据库查询对象
     * @param object                    $user       用户模型（需实现 UserContract）
     * @param string                    $permission 权限标识
     * @param string                    $userField  用户标识字段（默认 'user_id'）
     * @return Query|\think\db\BaseQuery
     */
    public function apply($query, $user, string $permission, string $userField = 'user_id')
    {
        // 超级管理员不限制
        if (method_exists($user, 'isSuperAdmin') && $user->isSuperAdmin()) {
            return $query;
        }

        // 调用自定义策略
        $policy = config('wise-auth.data_policy');
        if ($policy) {
            if ($policy instanceof \Closure) {
                return $policy($query, $user, $permission, $userField);
            }
            if (is_string($policy) && class_exists($policy)) {
                $instance = new $policy();
                if (is_callable($instance)) {
                    return $instance($query, $user, $permission, $userField);
                }
            }
        }

        // 内置策略：基于用户角色的 data_scope
        $userId   = $user->getAuthIdentifier();
        $userType = $user->getAuthUserType();

        $scopes = $this->getUserDataScopes($userId, $userType);

        if (empty($scopes)) {
            // 无数据权限范围 → 默认仅限自己
            return $query->where($userField, $userId);
        }

        // 合并所有角色的 data_scope
        $merged = $this->mergeScopes($scopes);

        return $this->buildScopeQuery($query, $merged, $userId, $userField);
    }

    /**
     * 获取用户所有角色的 data_scope
     *
     * @param int|string $userId
     * @param string     $userType
     * @return array
     */
    protected function getUserDataScopes($userId, string $userType): array
    {
        $records = UserRole::where('user_id', $userId)
            ->where('user_type', $userType)
            ->where(function ($query) {
                // expired_at 是 DATETIME 列，必须用 datetime 字符串比较，
                // 不能与 time() 的 int 时间戳比较（类型强转导致过滤恒真/恒假）。
                $query->whereNull('expired_at')
                      ->whereOr('expired_at', '>', date('Y-m-d H:i:s'));
            })
            ->select();

        $scopes = [];
        foreach ($records as $record) {
            if (!empty($record->data_scope)) {
                $decoded = is_string($record->data_scope)
                    ? json_decode($record->data_scope, true)
                    : $record->data_scope;
                if (is_array($decoded)) {
                    $scopes[] = $decoded;
                }
            }
        }

        return $scopes;
    }

    /**
     * 合并多个 data_scope
     *
     * 合并策略：数组取并集，布尔值 OR，字符串取最大范围。
     *
     * @param array $scopes
     * @return array
     */
    protected function mergeScopes(array $scopes): array
    {
        if (count($scopes) === 1) {
            return $scopes[0];
        }

        $merged = [];

        foreach ($scopes as $scope) {
            foreach ($scope as $key => $value) {
                if (!isset($merged[$key])) {
                    $merged[$key] = $value;
                } elseif (is_array($merged[$key]) && is_array($value)) {
                    // 数组取并集
                    $merged[$key] = array_values(array_unique(array_merge($merged[$key], $value)));
                } elseif (is_bool($merged[$key]) && is_bool($value)) {
                    // 布尔值 OR
                    $merged[$key] = $merged[$key] || $value;
                }
                // 其他类型：先到的值优先
            }
        }

        return $merged;
    }

    /**
     * 构建数据范围查询条件
     *
     * @param Query|\think\db\BaseQuery $query
     * @param array                     $scope      合并后的 data_scope
     * @param int|string                $userId     当前用户 ID
     * @param string                    $userField  用户标识字段
     * @return Query|\think\db\BaseQuery
     */
    protected function buildScopeQuery($query, array $scope, $userId, string $userField)
    {
        $conditions = [];

        // self_only: 仅自己
        if (!empty($scope['self_only'])) {
            $query->where($userField, $userId);
            return $query;
        }

        // dept_ids: 部门范围
        if (!empty($scope['dept_ids'])) {
            // 假设存在 dept_id 字段
            $conditions[] = function ($q) use ($scope) {
                $q->whereIn('dept_id', $scope['dept_ids']);
            };
        }

        // org_id: 组织范围
        if (!empty($scope['org_id'])) {
            $orgIds = is_array($scope['org_id']) ? $scope['org_id'] : [$scope['org_id']];
            $conditions[] = function ($q) use ($orgIds) {
                $q->whereIn('org_id', $orgIds);
            };
        }

        // 自定义条件
        if (!empty($scope['custom']) && is_array($scope['custom'])) {
            foreach ($scope['custom'] as $field => $value) {
                if (is_array($value)) {
                    $conditions[] = function ($q) use ($field, $value) {
                        $q->whereIn($field, $value);
                    };
                } else {
                    $conditions[] = function ($q) use ($field, $value) {
                        $q->where($field, $value);
                    };
                }
            }
        }

        // 应用所有范围条件（OR 连接）+ 自己的数据兜底
        if (!empty($conditions)) {
            $query->where(function ($q) use ($conditions, $userId, $userField) {
                // 范围条件
                foreach ($conditions as $cond) {
                    if (count($conditions) > 1) {
                        $q->whereOr($cond);
                    } else {
                        $cond($q);
                    }
                }
                // 兜底：自己的数据
                $q->whereOr($userField, $userId);
            });
        } else {
            // 无任何有效范围 → 仅限自己
            $query->where($userField, $userId);
        }

        return $query;
    }
}
