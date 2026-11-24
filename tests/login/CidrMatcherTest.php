<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\ip\CidrMatcher;

/**
 * IP CIDR 匹配器测试
 */
class CidrMatcherTest extends TestCase
{
    public function testExactMatch(): void
    {
        $this->assertTrue(CidrMatcher::matchSingle('192.168.1.10', '192.168.1.10'));
        $this->assertFalse(CidrMatcher::matchSingle('192.168.1.10', '192.168.1.11'));
    }

    public function testCidr24(): void
    {
        $this->assertTrue(CidrMatcher::matchSingle('192.168.1.10', '192.168.1.0/24'));
        $this->assertTrue(CidrMatcher::matchSingle('192.168.1.255', '192.168.1.0/24'));
        $this->assertFalse(CidrMatcher::matchSingle('192.168.2.1', '192.168.1.0/24'));
    }

    public function testCidr16(): void
    {
        $this->assertTrue(CidrMatcher::matchSingle('192.168.50.50', '192.168.0.0/16'));
        $this->assertFalse(CidrMatcher::matchSingle('192.169.0.1', '192.168.0.0/16'));
    }

    public function testCidr8(): void
    {
        $this->assertTrue(CidrMatcher::matchSingle('10.0.0.1', '10.0.0.0/8'));
        $this->assertTrue(CidrMatcher::matchSingle('10.255.255.255', '10.0.0.0/8'));
        $this->assertFalse(CidrMatcher::matchSingle('11.0.0.1', '10.0.0.0/8'));
    }

    public function testIPv6Cidr(): void
    {
        $this->assertTrue(CidrMatcher::matchSingle('2001:db8::1', '2001:db8::/32'));
        $this->assertFalse(CidrMatcher::matchSingle('2001:db9::1', '2001:db8::/32'));
    }

    public function testMatchMultiple(): void
    {
        $cidrs = ['10.0.0.0/8', '192.168.0.0/16'];
        $this->assertTrue(CidrMatcher::match('10.1.2.3', $cidrs));
        $this->assertTrue(CidrMatcher::match('192.168.5.5', $cidrs));
        $this->assertFalse(CidrMatcher::match('172.16.0.1', $cidrs));
    }

    public function testInvalidInput(): void
    {
        $this->assertFalse(CidrMatcher::matchSingle('999.999.999.999', '192.168.0.0/24'));
        $this->assertFalse(CidrMatcher::matchSingle('192.168.1.1', '999.168.0.0/24'));
    }

    public function testGetClientIpXForwardedFor(): void
    {
        $server = [
            'REMOTE_ADDR'             => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR'    => '203.0.113.5, 198.51.100.1',
        ];
        $this->assertEquals('203.0.113.5', CidrMatcher::getClientIp($server, true, ['127.0.0.1/32']));
    }

    public function testGetClientIpXRealIp(): void
    {
        $server = [
            'REMOTE_ADDR'       => '127.0.0.1',
            'HTTP_X_REAL_IP'    => '203.0.113.5',
        ];
        $this->assertEquals('203.0.113.5', CidrMatcher::getClientIp($server, true, ['127.0.0.1/32']));
    }

    public function testGetClientIpFallback(): void
    {
        $server = ['REMOTE_ADDR' => '203.0.113.5'];
        $this->assertEquals('203.0.113.5', CidrMatcher::getClientIp($server, false));
    }

    public function testGetClientIpXffDisabled(): void
    {
        $server = [
            'REMOTE_ADDR'          => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ];
        $this->assertEquals('127.0.0.1', CidrMatcher::getClientIp($server, false));
    }

    public function testGetClientIpTrustedProxies(): void
    {
        $server = [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ];
        $this->assertEquals('203.0.113.5', CidrMatcher::getClientIp($server, true, ['10.0.0.0/8']));
    }

    public function testGetClientIpUntrustedProxy(): void
    {
        $server = [
            'REMOTE_ADDR'          => '192.168.1.100',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ];
        $this->assertEquals('192.168.1.100', CidrMatcher::getClientIp($server, true, ['10.0.0.0/8']));
    }

    public function testGetClientIpEmptyTrustedProxies(): void
    {
        $server = [
            'REMOTE_ADDR'          => '192.168.1.100',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ];
        $this->assertEquals('192.168.1.100', CidrMatcher::getClientIp($server, true, []));
    }

    public function testGetClientIpSpoofedXffIsIgnoredWithoutTrustedProxies(): void
    {
        $server = [
            'REMOTE_ADDR'          => '203.0.113.9',
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
        ];
        $this->assertEquals('203.0.113.9', CidrMatcher::getClientIp($server, true, []));
    }
}
