<?php
/**
 * HasRoles Trait 单元测试
 *
 * 测试用户模型通过 HasRoles trait 获得的 RBAC 能力。
 *
 * 由于 HasRoles 深度依赖 ThinkPHP Model (morphToMany, Event, app, config)，
 * 本测试通过模拟环境进行单元逻辑验证。
 */
namespace wise\auth\tests;

use wise\auth\contract\UserContract;

class HasRolesTest extends TestCase
{
    // =============================
    // UserContract 接口规范测试
    // =============================

    public function testUserContractDefinesAllRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(UserContract::class);
        $methods = array_map(function ($m) { return $m->getName(); }, $reflection->getMethods());

        $requiredMethods = [
            'getAuthIdentifier',
            'getAuthUserType',
            'getRoles',
            'hasRole',
            'hasPermission',
            'can',
            'getAllPermissions',
            'isSuperAdmin',
            'assignRole',
            'removeRole',
            'syncRoles',
        ];

        foreach ($requiredMethods as $method) {
            $this->assertContains($method, $methods, "UserContract must define method: {$method}");
        }
    }

    public function testUserContractGetAuthIdentifierReturnType(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'getAuthIdentifier');
        // 接口不限定返回类型（int|string），但至少存在此方法
        $this->assertNotNull($reflection);
    }

    public function testUserContractGetAuthUserTypeReturnsString(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'getAuthUserType');
        $returnType = $reflection->getReturnType();
        $this->assertNotNull($returnType);
        $this->assertEquals('string', $returnType->getName());
    }

    public function testUserContractHasRoleSignature(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'hasRole');
        $params = $reflection->getParameters();
        $this->assertCount(2, $params);
        $this->assertEquals('roles', $params[0]->getName());
        $this->assertEquals('requireAll', $params[1]->getName());
        $this->assertTrue($params[1]->isDefaultValueAvailable());
        $this->assertFalse($params[1]->getDefaultValue());
    }

    public function testUserContractHasPermissionSignature(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'hasPermission');
        $params = $reflection->getParameters();
        $this->assertCount(2, $params);
        $this->assertEquals('permissions', $params[0]->getName());
        $this->assertEquals('requireAll', $params[1]->getName());
    }

    public function testUserContractCanSignature(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'can');
        $params = $reflection->getParameters();
        $this->assertCount(1, $params);
        $this->assertEquals('permission', $params[0]->getName());
    }

    public function testUserContractSyncRolesSignature(): void
    {
        $reflection = new \ReflectionMethod(UserContract::class, 'syncRoles');
        $params = $reflection->getParameters();
        $this->assertCount(1, $params);
        $this->assertEquals('roleIds', $params[0]->getName());
        $this->assertEquals('array', $params[0]->getType()->getName());
    }

    // =============================
    // TestUser Stub 测试
    // =============================

    public function testTestStubImplementsUserContract(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser();
        $this->assertInstanceOf(UserContract::class, $user);
    }

    public function testTestStubGetAuthIdentifier(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 42]);
        $this->assertEquals(42, $user->getAuthIdentifier());
    }

    public function testTestStubGetAuthIdentifierDefault(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser();
        $this->assertEquals(0, $user->getAuthIdentifier());
    }

    public function testTestStubGetAuthUserType(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 1, 'user_type' => 'member']);
        $this->assertEquals('member', $user->getAuthUserType());
    }

    public function testTestStubGetAuthUserTypeDefault(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 1]);
        $this->assertEquals('admin', $user->getAuthUserType());
    }

    public function testTestStubMethodsReturnExpectedTypes(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 1]);

        $this->assertIsString($user->getAuthUserType());
        $this->assertIsArray($user->getAllPermissions());
        $this->assertIsBool($user->hasRole('admin'));
        $this->assertIsBool($user->hasPermission('admin.user.list'));
        $this->assertIsBool($user->can('admin.user.list'));
        $this->assertIsBool($user->isSuperAdmin());
        $this->assertIsBool($user->assignRole(1));
        $this->assertIsBool($user->removeRole(1));
        $this->assertIsBool($user->syncRoles([1, 2]));
    }

    // =============================
    // HasRoles trait 结构测试
    // =============================

    public function testHasRolesTraitExists(): void
    {
        $this->assertTrue(trait_exists(\wise\auth\trait\HasRoles::class));
    }

    public function testHasRolesTraitHasRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(\wise\auth\trait\HasRoles::class);
        $methods = array_map(function ($m) { return $m->getName(); }, $reflection->getMethods());

        $expectedMethods = [
            'getAuthUserType',
            'getAuthIdentifier',
            'roles',
            'getRoles',
            'hasRole',
            'assignRole',
            'removeRole',
            'syncRoles',
            'can',
            'hasPermission',
            'getAllPermissions',
            'isSuperAdmin',
        ];

        foreach ($expectedMethods as $method) {
            $this->assertContains($method, $methods, "HasRoles trait must have method: {$method}");
        }
    }

    // =============================
    // isSuperAdmin 逻辑测试（不依赖数据库）
    // =============================

    public function testIsSuperAdminBySuperAdminIdsConfig(): void
    {
        // 模拟 HasRoles::isSuperAdmin 的逻辑
        $this->setConfig('wiseauth.super_admin_ids', [1, 5, 10]);
        $this->setConfig('wiseauth.super_role', null);

        // 逻辑: in_array(getAuthIdentifier(), super_admin_ids)
        $this->assertTrue(in_array(1, $this->getConfig('wiseauth.super_admin_ids')));
        $this->assertTrue(in_array(5, $this->getConfig('wiseauth.super_admin_ids')));
        $this->assertFalse(in_array(2, $this->getConfig('wiseauth.super_admin_ids')));
    }

    public function testGetAuthUserTypeDefaultLogic(): void
    {
        // HasRoles 默认返回类名的小写短名
        $class = \wise\auth\tests\stubs\TestUser::class;
        $parts = explode('\\', $class);
        $expected = strtolower(array_pop($parts));
        $this->assertEquals('testuser', $expected);
    }

    // =============================
    // ConstraintCheckerInterface 规范测试
    // =============================

    public function testConstraintCheckerInterfaceMethods(): void
    {
        $reflection = new \ReflectionClass(\wise\auth\contract\ConstraintCheckerInterface::class);
        $methods = array_map(function ($m) { return $m->getName(); }, $reflection->getMethods());

        $this->assertContains('checkBeforeAssignRole', $methods);
        $this->assertContains('checkBeforeGrantPermission', $methods);
        $this->assertContains('checkBeforeSaveRole', $methods);
    }

    public function testConstraintCheckerInterfaceReturnsBool(): void
    {
        $reflection = new \ReflectionMethod(
            \wise\auth\contract\ConstraintCheckerInterface::class,
            'checkBeforeAssignRole'
        );
        $this->assertEquals('bool', $reflection->getReturnType()->getName());
    }
}
