<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\device\DeviceFingerprint;

/**
 * 设备指纹测试
 */
class DeviceFingerprintTest extends TestCase
{
    public function testSameInputsSameFingerprint(): void
    {
        $fp = new DeviceFingerprint('salt-A');
        $a = $fp->generate('UA-A', '1.2.3.4', 'zh-CN', 'gzip');
        $b = $fp->generate('UA-A', '1.2.3.4', 'zh-CN', 'gzip');
        $this->assertEquals($a, $b);
    }

    public function testDifferentUaDifferentFingerprint(): void
    {
        $fp = new DeviceFingerprint('salt');
        $a = $fp->generate('UA-A', '1.2.3.4');
        $b = $fp->generate('UA-B', '1.2.3.4');
        $this->assertNotEquals($a, $b);
    }

    public function testDifferentIpSameFingerprint(): void
    {
        $fp = new DeviceFingerprint('salt');
        $a = $fp->generate('UA', '1.2.3.4');
        $b = $fp->generate('UA', '1.2.3.5');
        $this->assertEquals($a, $b, 'SEC-4: IP 不再影响指纹');
    }

    public function testDifferentSaltDifferentFingerprint(): void
    {
        $a = (new DeviceFingerprint('salt-1'))->generate('UA', '1.2.3.4');
        $b = (new DeviceFingerprint('salt-2'))->generate('UA', '1.2.3.4');
        $this->assertNotEquals($a, $b);
    }

    public function testFingerprintIsSha256Hex(): void
    {
        $fp = new DeviceFingerprint('salt');
        $hash = $fp->generate('UA', '1.2.3.4');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash);
    }

    public function testFromRequest(): void
    {
        $server = [
            'HTTP_USER_AGENT'      => 'Mozilla/5.0 (iPhone)',
            'HTTP_ACCEPT_LANGUAGE' => 'zh-CN,zh;q=0.9',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
        ];
        $a = DeviceFingerprint::fromRequest($server, '1.2.3.4', 'salt', true);
        $b = DeviceFingerprint::fromRequest($server, '1.2.3.4', 'salt', true);
        $this->assertEquals($a, $b);
        $this->assertNotEmpty($a);
    }

    public function testFromRequestDifferentIpSameFingerprint(): void
    {
        $server = [
            'HTTP_USER_AGENT'      => 'Mozilla/5.0 (iPhone)',
            'HTTP_ACCEPT_LANGUAGE' => 'zh-CN,zh;q=0.9',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
        ];
        $a = DeviceFingerprint::fromRequest($server, '1.2.3.4', 'salt', true);
        $b = DeviceFingerprint::fromRequest($server, '5.6.7.8', 'salt', true);
        $this->assertEquals($a, $b, 'SEC-4: 不同 IP 相同 UA 应产生相同指纹');
    }
}
