<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\exception\AccountLockedException;
use wise\login\exception\CaptchaInvalidException;
use wise\login\exception\IpBlockedException;
use wise\login\exception\TwoFactorRequiredException;
use wise\login\exception\BackupCodeInvalidException;
use wise\login\exception\LoginException;
use wise\support\exception\WiseException;

/**
 * 异常类测试
 */
class ExceptionTest extends TestCase
{
    public function testIpBlockedException(): void
    {
        $e = new IpBlockedException('test', ['ip' => '1.2.3.4']);
        $this->assertEquals(403, $e->getStatusCode());
        $this->assertEquals(60010, $e->getErrorCode());
        $this->assertEquals(['ip' => '1.2.3.4'], $e->getData());
    }

    public function testAccountLockedException(): void
    {
        $e = new AccountLockedException('test', ['ttl' => 600]);
        $this->assertEquals(423, $e->getStatusCode());
        $this->assertEquals(60020, $e->getErrorCode());
    }

    public function testCaptchaInvalidException(): void
    {
        $e = new CaptchaInvalidException();
        $this->assertEquals(422, $e->getStatusCode());
    }

    public function testTwoFactorRequiredException(): void
    {
        $e = new TwoFactorRequiredException('2FA required');
        $this->assertEquals(401, $e->getStatusCode());
        $this->assertEquals(60040, $e->getErrorCode());
    }

    public function testBackupCodeInvalidException(): void
    {
        $e = new BackupCodeInvalidException();
        $this->assertEquals(422, $e->getStatusCode());
        $this->assertEquals(60050, $e->getErrorCode());
    }

    public function testToArray(): void
    {
        $e = new IpBlockedException('test msg', ['k' => 'v']);
        $arr = $e->toArray();
        $this->assertEquals(60010, $arr['code']);
        $this->assertEquals('test msg', $arr['msg']);
        $this->assertEquals(['k' => 'v'], $arr['data']);
    }

    public function testExceptionInheritance(): void
    {
        $e = new IpBlockedException();
        $this->assertInstanceOf(LoginException::class, $e);
        $this->assertInstanceOf(WiseException::class, $e);
        $this->assertInstanceOf(\RuntimeException::class, $e);
    }
}
