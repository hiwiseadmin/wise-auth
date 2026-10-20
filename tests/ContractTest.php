<?php
/**
 * 契约接口单元测试
 *
 * 测试 UserContract 和 ConstraintCheckerInterface 接口规范。
 */
namespace wise\auth\tests;

use wise\auth\contract\UserContract;
use wise\auth\contract\ConstraintCheckerInterface;

class ContractTest extends TestCase
{
    // =============================
    // UserContract 接口测试
    // =============================

    public function testUserContractExists(): void
    {
        $this->assertTrue(interface_exists(UserContract::class));
    }

    public function testUserContractIsInterface(): void
    {
        $reflection = new \ReflectionClass(UserContract::class);
        $this->assertTrue($reflection->isInterface());
    }

    public function testUserContractMethodCount(): void
    {
        $reflection = new \ReflectionClass(UserContract::class);
        $methods = $reflection->getMethods();
        // 11 个方法
        $this->assertCount(11, $methods);
    }

    public function testUserContractHasAllRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(UserContract::class);
        $methodNames = array_map(function ($m) { return $m->getName(); }, $reflection->getMethods());

        $required = [
            'getAuthIdentifier', 'getAuthUserType', 'getRoles',
            'hasRole', 'hasPermission', 'can',
            'getAllPermissions', 'isSuperAdmin',
            'assignRole', 'removeRole', 'syncRoles',
        ];

        foreach ($required as $method) {
            $this->assertContains($method, $methodNames);
        }
    }

    // =============================
    // ConstraintCheckerInterface 测试
    // =============================

    public function testConstraintCheckerInterfaceExists(): void
    {
        $this->assertTrue(interface_exists(ConstraintCheckerInterface::class));
    }

    public function testConstraintCheckerInterfaceIsInterface(): void
    {
        $reflection = new \ReflectionClass(ConstraintCheckerInterface::class);
        $this->assertTrue($reflection->isInterface());
    }

    public function testConstraintCheckerInterfaceMethodCount(): void
    {
        $reflection = new \ReflectionClass(ConstraintCheckerInterface::class);
        $methods = $reflection->getMethods();
        $this->assertCount(3, $methods);
    }

    public function testConstraintCheckerInterfaceCheckBeforeAssignRole(): void
    {
        $reflection = new \ReflectionMethod(ConstraintCheckerInterface::class, 'checkBeforeAssignRole');
        $this->assertNotNull($reflection);
        $params = $reflection->getParameters();
        $this->assertCount(4, $params);
    }

    public function testConstraintCheckerInterfaceCheckBeforeGrantPermission(): void
    {
        $reflection = new \ReflectionMethod(ConstraintCheckerInterface::class, 'checkBeforeGrantPermission');
        $this->assertNotNull($reflection);
        $params = $reflection->getParameters();
        $this->assertCount(3, $params);
    }

    public function testConstraintCheckerInterfaceCheckBeforeSaveRole(): void
    {
        $reflection = new \ReflectionMethod(ConstraintCheckerInterface::class, 'checkBeforeSaveRole');
        $this->assertNotNull($reflection);
        $params = $reflection->getParameters();
        $this->assertCount(2, $params);
    }

    // =============================
    // Service 提供者测试
    // =============================

    public function testServiceProviderExists(): void
    {
        $this->assertTrue(class_exists(\wise\auth\Service::class));
    }

    public function testServiceProviderExtendsThinkService(): void
    {
        $app = new \think\App();
        $service = new \wise\auth\Service($app);
        $this->assertInstanceOf(\think\Service::class, $service);
    }

    public function testServiceProviderHasRegisterMethod(): void
    {
        $this->assertTrue(method_exists(\wise\auth\Service::class, 'register'));
    }

    public function testServiceProviderHasBootMethod(): void
    {
        $this->assertTrue(method_exists(\wise\auth\Service::class, 'boot'));
    }

    // =============================
    // 命名空间一致性测试
    // =============================

    public function testAllSourceClassesExist(): void
    {
        $classes = [
            \wise\auth\Service::class,
            \wise\auth\Rbac::class,
            \wise\auth\model\Role::class,
            \wise\auth\model\Permission::class,
            \wise\auth\model\UserRole::class,
            \wise\auth\service\RbacManager::class,
            \wise\auth\service\PermissionRegistrar::class,
            \wise\auth\middleware\RbacMiddleware::class,
            \wise\auth\subscribe\AuthEventSubscriber::class,
            \wise\auth\event\RoleChanged::class,
            \wise\auth\event\PermissionChanged::class,
            \wise\auth\exception\UnauthorizedException::class,
            \wise\auth\exception\ConstraintViolationException::class,
            \wise\auth\contract\UserContract::class,
            \wise\auth\contract\ConstraintCheckerInterface::class,
            \wise\auth\traits\CacheKeyHelper::class,
            \wise\auth\traits\HasRoles::class,
        ];

        foreach ($classes as $class) {
            $this->assertTrue(class_exists($class) || trait_exists($class) || interface_exists($class),
                "Class/Trait/Interface {$class} should exist");
        }
    }
}
