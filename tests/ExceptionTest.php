<?php
/**
 * 异常类单元测试
 *
 * 测试 UnauthorizedException 和 ConstraintViolationException 的所有行为。
 */
namespace wise\auth\tests;

use wise\auth\exception\UnauthorizedException;
use wise\auth\exception\ConstraintViolationException;

class ExceptionTest extends TestCase
{
    // =============================
    // UnauthorizedException 测试
    // =============================

    public function testUnauthorizedExceptionDefaultMessage(): void
    {
        $e = new UnauthorizedException();
        $this->assertEquals('Unauthorized', $e->getMessage());
        $this->assertEquals('', $e->getPermission());
        $this->assertEquals(403, $e->getStatusCode());
        $this->assertEquals(0, $e->getCode());
    }

    public function testUnauthorizedExceptionCustomMessage(): void
    {
        $e = new UnauthorizedException('Permission denied');
        $this->assertEquals('Permission denied', $e->getMessage());
        $this->assertEquals('', $e->getPermission());
        $this->assertEquals(403, $e->getStatusCode());
    }

    public function testUnauthorizedExceptionWithPermission(): void
    {
        $e = new UnauthorizedException('Access denied', 'admin.user.delete');
        $this->assertEquals('admin.user.delete', $e->getPermission());
        $this->assertEquals('Access denied', $e->getMessage());
        $this->assertEquals(403, $e->getStatusCode());
    }

    public function testUnauthorizedExceptionWithCode(): void
    {
        $e = new UnauthorizedException('Forbidden', 'admin.user.list', 1001);
        $this->assertEquals('admin.user.list', $e->getPermission());
        $this->assertEquals(1001, $e->getCode());
        $this->assertEquals('Forbidden', $e->getMessage());
    }

    public function testUnauthorizedExceptionSetStatusCode(): void
    {
        $e = new UnauthorizedException();
        $result = $e->setStatusCode(401);
        $this->assertSame($e, $result); // 链式调用返回自身
        $this->assertEquals(401, $e->getStatusCode());
    }

    public function testUnauthorizedExceptionSetStatusCode401(): void
    {
        $e = new UnauthorizedException('Unauthorized access');
        $e->setStatusCode(401);
        $this->assertEquals(401, $e->getStatusCode());
    }

    public function testUnauthorizedExceptionSetStatusCode500(): void
    {
        $e = new UnauthorizedException();
        $e->setStatusCode(500);
        $this->assertEquals(500, $e->getStatusCode());
    }

    public function testUnauthorizedExceptionExtendsThinkException(): void
    {
        $e = new UnauthorizedException();
        $this->assertInstanceOf(\think\Exception::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
    }

    public function testUnauthorizedExceptionPermissionIsString(): void
    {
        $e = new UnauthorizedException('test', 'my.permission');
        $this->assertIsString($e->getPermission());
    }

    // =============================
    // ConstraintViolationException 测试
    // =============================

    public function testConstraintViolationExceptionDefaultValues(): void
    {
        $e = new ConstraintViolationException();
        $this->assertEquals('', $e->getMessage());
        $this->assertEquals('', $e->getConstraintType());
        $this->assertEquals(0, $e->getCode());
    }

    public function testConstraintViolationExceptionWithMessage(): void
    {
        $e = new ConstraintViolationException('Mutual exclusion violation');
        $this->assertEquals('Mutual exclusion violation', $e->getMessage());
        $this->assertEquals('', $e->getConstraintType());
    }

    public function testConstraintViolationExceptionWithType(): void
    {
        $e = new ConstraintViolationException('Error', 'mutual_exclusion');
        $this->assertEquals('mutual_exclusion', $e->getConstraintType());
        $this->assertEquals('Error', $e->getMessage());
    }

    public function testConstraintViolationExceptionWithCode(): void
    {
        $e = new ConstraintViolationException('Error', 'cardinality', 409);
        $this->assertEquals('cardinality', $e->getConstraintType());
        $this->assertEquals('Error', $e->getMessage());
        $this->assertEquals(409, $e->getCode());
    }

    public function testConstraintViolationExceptionTypeMutualExclusion(): void
    {
        $e = new ConstraintViolationException('', 'mutual_exclusion');
        $this->assertEquals('mutual_exclusion', $e->getConstraintType());
    }

    public function testConstraintViolationExceptionTypeCardinality(): void
    {
        $e = new ConstraintViolationException('', 'cardinality');
        $this->assertEquals('cardinality', $e->getConstraintType());
    }

    public function testConstraintViolationExceptionTypePrerequisite(): void
    {
        $e = new ConstraintViolationException('', 'prerequisite');
        $this->assertEquals('prerequisite', $e->getConstraintType());
    }

    public function testConstraintViolationExceptionExtendsThinkException(): void
    {
        $e = new ConstraintViolationException();
        $this->assertInstanceOf(\think\Exception::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
    }

    public function testConstraintViolationExceptionIsString(): void
    {
        $e = new ConstraintViolationException('test constraint', 'prerequisite');
        $this->assertIsString($e->getConstraintType());
        $this->assertIsString($e->getMessage());
    }
}
