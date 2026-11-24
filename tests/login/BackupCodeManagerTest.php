<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\totp\BackupCodeManager;
use wise\login\contract\TotpUserInterface;

/**
 * 备份码测试
 */
class BackupCodeManagerTest extends TestCase
{
    /**
     * 备份码内置限流（失败计数 + 冷却）落在缓存里，且匿名测试用户的
     * 限流键相同；不复位会因上一个用例的失败次数而误判为「已冷却」。
     */
    protected function setUp(): void
    {
        parent::setUp();
        \wise_auth_test_reset();
    }

    public function testGenerateCount(): void
    {
        $mgr = new BackupCodeManager(10, 8);
        $result = $mgr->generate();
        $this->assertCount(10, $result['plain']);
        $this->assertCount(10, $result['hashed']);
    }

    public function testEachCodeIsUnique(): void
    {
        $mgr = new BackupCodeManager(10, 8);
        $result = $mgr->generate();
        $this->assertCount(10, array_unique($result['plain']));
    }

    public function testCodeLength(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $result = $mgr->generate();
        foreach ($result['plain'] as $code) {
            $this->assertEquals(8, strlen($code));
        }
    }

    public function testConsumeValidCode(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $user = $this->makeUser();
        $codes = $mgr->generate();
        $user->setBackupCodes($codes['hashed']);

        $this->assertTrue($mgr->consume($user, $codes['plain'][0]));
        $this->assertFalse($mgr->consume($user, $codes['plain'][0]), '不应能重复使用');
        $this->assertCount(4, $user->getBackupCodes());
    }

    public function testConsumeInvalidCode(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $user = $this->makeUser();
        $user->setBackupCodes($mgr->generate()['hashed']);

        $this->assertFalse($mgr->consume($user, 'AAAA-AAAA'));
        $this->assertFalse($mgr->consume($user, ''));
    }

    public function testCaseInsensitive(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $user = $this->makeUser();
        $codes = $mgr->generate();
        $user->setBackupCodes($codes['hashed']);

        $upper = $codes['plain'][0];
        $lower = strtolower($upper);
        $this->assertTrue($mgr->consume($user, $lower));
    }

    public function testIsValid(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $user = $this->makeUser();
        $codes = $mgr->generate();
        $user->setBackupCodes($codes['hashed']);

        $this->assertTrue($mgr->isValid($user, $codes['plain'][0]));
        $this->assertTrue($mgr->isValid($user, $codes['plain'][0]), 'isValid 不应消费');
    }

    public function testRemainingCount(): void
    {
        $mgr = new BackupCodeManager(5, 8);
        $user = $this->makeUser();
        $user->setBackupCodes($mgr->generate()['hashed']);

        $this->assertEquals(5, $mgr->remainingCount($user));
        $mgr->consume($user, $user->getBackupCodes() ? array_keys($user->getBackupCodes())[0] : '');
    }

    protected function makeUser(): TotpUserInterface
    {
        return new class implements TotpUserInterface {
            private string $secret = '';
            private array $codes = [];
            private array $recoveryCodes = [];
            public function getTotpLabel(): string { return 'test'; }
            public function getTotpUserType(): string { return 'user'; }
            public function getTotpSecret(): ?string { return $this->secret; }
            public function setTotpSecret(?string $secret): void { $this->secret = $secret; }
            public function getBackupCodes(): array { return $this->codes; }
            public function setBackupCodes(array $codes): void { $this->codes = $codes; }
            public function getRecoveryCodes(): array { return $this->recoveryCodes; }
            public function setRecoveryCodes(array $codes): void { $this->recoveryCodes = $codes; }
            public function isTotpEnabled(): bool { return true; }
            public function setTotpEnabled(bool $enabled): void {}
        };
    }
}
