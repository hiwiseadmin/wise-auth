<?php
/**
 * Rbac Facade 单元测试
 *
 * 测试 Facade 代理是否正确指向 RbacManager。
 */
namespace wise\auth\tests;

use wise\auth\facade\Rbac;
use wise\auth\service\RbacManager;

class FacadeTest extends TestCase
{
    public function testFacadeGetFacadeClass(): void
    {
        $reflection = new \ReflectionClass(Rbac::class);
        $method = $reflection->getMethod('getFacadeClass');
        $method->setAccessible(true);
        $result = $method->invoke(null);
        $this->assertEquals(RbacManager::class, $result);
    }

    public function testFacadeClassIsCorrectNamespace(): void
    {
        $this->assertEquals('wise\\auth\\facade\\Rbac', Rbac::class);
    }

    public function testFacadeExtendsThinkFacade(): void
    {
        $this->assertInstanceOf(\think\Facade::class, new Rbac());
    }

    public function testFacadeTargetClassExists(): void
    {
        $this->assertTrue(class_exists(RbacManager::class));
    }

    public function testFacadeGetFacadeClassReturnsString(): void
    {
        $reflection = new \ReflectionClass(Rbac::class);
        $method = $reflection->getMethod('getFacadeClass');
        $method->setAccessible(true);
        $result = $method->invoke(null);
        $this->assertIsString($result);
    }

    public function testFacadeTargetIsRbacManagerExactly(): void
    {
        $reflection = new \ReflectionClass(Rbac::class);
        $method = $reflection->getMethod('getFacadeClass');
        $method->setAccessible(true);
        $result = $method->invoke(null);
        $this->assertEquals('wise\\auth\\service\\RbacManager', $result);
    }
}
