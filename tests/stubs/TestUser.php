<?php
/**
 * 测试用用户模型 Stub
 *
 * 完整实现 UserContract，用于 HasRoles trait / RbacMiddleware / RbacManager 测试。
 *
 * 注意：签名必须与 `wise\auth\contract\UserContract` **逐字兼容**（参数类型、可选参数、
 * 返回类型）。接口演进后若忘记同步本 stub，PHP 会直接 fatal：
 *   Declaration of ...::getAuthIdentifier() must be compatible with
 *   ...UserContract::getAuthIdentifier(): string|int
 * 该 fatal 发生在类加载阶段，会中断整个测试进程（后面的用例一个都不跑）。
 */
namespace wise\auth\tests\stubs;

use wise\auth\contract\UserContract;

class TestUser implements UserContract
{
    protected $id = 0;
    protected $attributes = [];
    protected $roles = [];

    /**
     * 供测试注入的权限标识（不查库）
     *
     * @var string[]
     */
    protected array $permissions = [];

    /**
     * 最近一次 assignRole/removeRole/syncRoles 的入参记录（供断言）
     *
     * @var array<string, mixed>
     */
    public array $lastRoleCall = [];

    public function __construct(array $attributes = [])
    {
        $this->attributes = $attributes;
        $this->id         = $attributes['id'] ?? 0;

        if (isset($attributes['roles']) && is_array($attributes['roles'])) {
            $this->roles = $attributes['roles'];
        }

        if (isset($attributes['permissions']) && is_array($attributes['permissions'])) {
            $this->permissions = $attributes['permissions'];
        }
    }

    public function getKey()
    {
        return $this->id;
    }

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthUserType(): string
    {
        return $this->attributes['user_type'] ?? 'admin';
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function hasRole(string|array $roles, bool $requireAll = false): bool
    {
        $needles = array_values(array_filter((array) $roles, static fn ($r): bool => $r !== ''));
        if ($needles === []) {
            return false;
        }

        $owned = array_map(static function ($role): string {
            if (is_object($role)) {
                return (string) ($role->slug ?? $role->name ?? '');
            }

            return (string) $role;
        }, (array) $this->roles);

        $hits = array_intersect($needles, $owned);

        return $requireAll ? count($hits) === count($needles) : $hits !== [];
    }

    public function hasPermission(string|array $permissions, bool $requireAll = false): bool
    {
        $needles = array_values(array_filter((array) $permissions, static fn ($p): bool => $p !== ''));
        if ($needles === []) {
            return false;
        }

        $hits = array_intersect($needles, $this->permissions);

        return $requireAll ? count($hits) === count($needles) : $hits !== [];
    }

    public function can(string $permission): bool
    {
        return $this->hasPermission($permission);
    }

    public function getAllPermissions(): array
    {
        return $this->permissions;
    }

    public function isSuperAdmin(): bool
    {
        return false;
    }

    public function assignRole(int|string|array $roleIds, ?int $expiredAt = null): bool
    {
        $this->lastRoleCall = ['method' => 'assignRole', 'roleIds' => $roleIds, 'expiredAt' => $expiredAt];

        return true;
    }

    public function removeRole(int|string|array $roleIds): bool
    {
        $this->lastRoleCall = ['method' => 'removeRole', 'roleIds' => $roleIds];

        return true;
    }

    public function syncRoles(array $roleIds, ?int $expiredAt = null): bool
    {
        $this->lastRoleCall = ['method' => 'syncRoles', 'roleIds' => $roleIds, 'expiredAt' => $expiredAt];

        return true;
    }

    public function refreshPermissions(): array
    {
        return $this->permissions;
    }

    public function forgetPermissions(): void
    {
        $this->permissions = [];
    }

    /**
     * 供测试注入权限
     *
     * @param string[] $permissions
     */
    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;
    }

    /**
     * 供测试重置角色
     *
     * @param array $roles
     */
    public function setRoles(array $roles): void
    {
        $this->roles = $roles;
    }

    /**
     * Set attributes for testing
     */
    public function setAttribute(string $key, $value): void
    {
        $this->attributes[$key] = $value;
    }
}
