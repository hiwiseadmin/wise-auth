<?php
/**
 * 测试用用户模型 Stub
 *
 * 实现 UserContract 接口，用于 HasRoles trait 测试。
 */
namespace wise\auth\tests\stubs;

use wise\auth\contract\UserContract;

class TestUser implements UserContract
{
    protected $id = 0;
    protected $attributes = [];
    protected $roles = [];

    public function __construct(array $attributes = [])
    {
        $this->attributes = $attributes;
        $this->id = $attributes['id'] ?? 0;
    }

    public function getKey()
    {
        return $this->id;
    }

    public function getAuthIdentifier()
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

    public function hasRole($roles, bool $requireAll = false): bool
    {
        return false;
    }

    public function hasPermission($permissions, bool $requireAll = false): bool
    {
        return false;
    }

    public function can(string $permission): bool
    {
        return false;
    }

    public function getAllPermissions(): array
    {
        return [];
    }

    public function isSuperAdmin(): bool
    {
        return false;
    }

    public function assignRole($roleIds): bool
    {
        return true;
    }

    public function removeRole($roleIds): bool
    {
        return true;
    }

    public function syncRoles(array $roleIds): bool
    {
        return true;
    }

    /**
     * Set attributes for testing
     */
    public function setAttribute(string $key, $value): void
    {
        $this->attributes[$key] = $value;
    }
}
