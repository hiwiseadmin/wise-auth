<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\totp\Base32;
use wise\login\totp\TotpManager;

/**
 * TOTP 测试
 */
class TotpTest extends TestCase
{
    /**
     * 校验通过会占用「重放标记」缓存键，且依赖容器可用；统一复位避免跨用例污染。
     */
    protected function setUp(): void
    {
        parent::setUp();
        \wise_auth_test_reset();
    }

    public function testBase32Roundtrip(): void
    {
        $cases = [
            '',
            'f',
            'fo',
            'foo',
            'foob',
            'fooba',
            'foobar',
            'Hello, World!',
        ];
        foreach ($cases as $raw) {
            $encoded = Base32::encode($raw);
            $decoded = Base32::decode($encoded);
            $this->assertEquals($raw, $decoded, "Roundtrip failed for: {$raw}");
        }
    }

    public function testBase32KnownVector(): void
    {
        $this->assertEquals('MY======', Base32::encode('f'));
        $this->assertEquals('MZXQ====', Base32::encode('fo'));
        $this->assertEquals('MZXW6===', Base32::encode('foo'));
        $this->assertEquals('MZXW6YQ=', Base32::encode('foob'));
        $this->assertEquals('MZXW6YTB', Base32::encode('fooba'));
        $this->assertEquals('MZXW6YTBOI======', Base32::encode('foobar'));
    }

    public function testSecretGeneration(): void
    {
        $manager = new TotpManager();
        $secret = $manager->generateSecret();
        $this->assertNotEmpty($secret);
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }

    public function testTotpCodeFormat(): void
    {
        $manager = new TotpManager();
        $secret = $manager->generateSecret();
        $timestep = (int) floor(time() / 30);
        $code = $manager->generateAt($secret, $timestep);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
    }

    public function testTotpVerify(): void
    {
        $manager = new TotpManager();
        $secret = $manager->generateSecret();
        $timestep = (int) floor(time() / 30);
        $code = $manager->generateAt($secret, $timestep);

        $user = $this->makeUser($secret);
        $this->assertTrue($manager->verify($user, $code));
    }

    public function testTotpRejectsInvalid(): void
    {
        $manager = new TotpManager();
        $secret = $manager->generateSecret();
        $user = $this->makeUser($secret);
        $this->assertFalse($manager->verify($user, '000000'));
        $this->assertFalse($manager->verify($user, '12345'));
        $this->assertFalse($manager->verify($user, 'abcdef'));
    }

    public function testTotpRfc6238Vector(): void
    {
        $secret = Base32::encode('12345678901234567890');
        $manager = new TotpManager([
            'algorithm' => 'sha1',
            'digits'    => 8,
            'period'    => 30,
        ]);

        $this->assertEquals('24083773', $manager->generateAt($secret, 59));
        $this->assertEquals('14510233', $manager->generateAt($secret, 1111111109));
        $this->assertEquals('54073950', $manager->generateAt($secret, 1111111111));
        $this->assertEquals('03965462', $manager->generateAt($secret, 1234567890));
        $this->assertEquals('21054266', $manager->generateAt($secret, 2000000000));
    }

    public function testGetQrUri(): void
    {
        $manager = new TotpManager();
        $user = $this->makeUser('JBSWY3DPEHPK3PXP');
        $uri = $manager->getQrUri($user);
        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=JBSWY3DPEHPK3PXP', $uri);
        $this->assertStringContainsString('digits=6', $uri);
    }

    public function testGetQrDataUri(): void
    {
        $manager = new TotpManager();
        $user = $this->makeUser('JBSWY3DPEHPK3PXP');
        $uri = $manager->getQrDataUri($user);
        $this->assertStringStartsWith('data:image/', $uri);

        if (str_starts_with($uri, 'data:image/svg+xml;base64,')) {
            $decoded = base64_decode(substr($uri, strlen('data:image/svg+xml;base64,')));
            $this->assertStringContainsString('<svg', $decoded);
        }
    }

    protected function makeUser(string $secret): object
    {
        return new class($secret) implements \wise\login\contract\TotpUserInterface {
            public string $secret;
            public array $codes = [];
            public array $recoveryCodes = [];
            public function __construct(string $secret) { $this->secret = $secret; }
            public function getTotpLabel(): string { return 'test@example.com'; }
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
