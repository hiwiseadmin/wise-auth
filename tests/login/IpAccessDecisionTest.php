<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use wise\login\ip\IpAccessDecision;

/**
 * IP 访问判定测试
 *
 * 该判定同时被 admin 应用级中间件与登录守卫 Action 使用，
 * 因此这里是「两份实现曾经各写一遍」的契约回归：顺序、原因、白名单优先都不能变。
 */
class IpAccessDecisionTest extends TestCase
{
    public function testBlacklistModeBlocksMatchedIp(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], [], IpAccessDecision::MODE_BLACKLIST);
        $result   = $decision->evaluate('192.168.1.100');

        $this->assertFalse($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_BLACKLIST, $result['reason']);
        $this->assertFalse($result['whitelist_hit']);
    }

    public function testBlacklistModePassesCleanIp(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], [], IpAccessDecision::MODE_BLACKLIST);
        $result   = $decision->evaluate('10.0.0.1');

        $this->assertTrue($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_DEFAULT, $result['reason']);
    }

    public function testBlacklistModeIgnoresWhitelist(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], ['192.168.1.0/24'], IpAccessDecision::MODE_BLACKLIST);
        $result   = $decision->evaluate('192.168.1.100');

        $this->assertFalse($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_BLACKLIST, $result['reason']);
    }

    public function testWhitelistModeBlocksNonWhitelisted(): void
    {
        $decision = new IpAccessDecision([], ['192.168.1.0/24'], IpAccessDecision::MODE_WHITELIST);
        $result   = $decision->evaluate('10.0.0.1');

        $this->assertFalse($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_NOT_IN_WHITELIST, $result['reason']);
    }

    public function testWhitelistModePassesMatchedIp(): void
    {
        $decision = new IpAccessDecision([], ['192.168.1.0/24'], IpAccessDecision::MODE_WHITELIST);
        $result   = $decision->evaluate('192.168.1.10');

        $this->assertTrue($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_WHITELIST, $result['reason']);
        $this->assertTrue($result['whitelist_hit']);
    }

    public function testBothModePrefersWhitelistOverBlacklist(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], ['192.168.1.0/24'], IpAccessDecision::MODE_BOTH);
        $result   = $decision->evaluate('192.168.1.10');

        $this->assertTrue($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_WHITELIST, $result['reason']);
    }

    public function testBothModeFallsBackToBlacklist(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], ['10.0.0.0/8'], IpAccessDecision::MODE_BOTH);
        $result   = $decision->evaluate('192.168.1.10');

        $this->assertFalse($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_BLACKLIST, $result['reason']);
    }

    public function testBothModePassesIpInNeitherList(): void
    {
        $decision = new IpAccessDecision(['192.168.0.0/16'], ['10.0.0.0/8'], IpAccessDecision::MODE_BOTH);
        $result   = $decision->evaluate('172.16.0.1');

        $this->assertTrue($result['allowed']);
        $this->assertSame(IpAccessDecision::REASON_DEFAULT, $result['reason']);
    }

    public function testEmptyListsPassEverything(): void
    {
        $decision = new IpAccessDecision([], [], IpAccessDecision::MODE_BLACKLIST);
        $this->assertTrue($decision->evaluate('203.0.113.9')['allowed']);
    }

    public function testInvalidModeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP guard mode');

        new IpAccessDecision([], [], 'unknown');
    }

    public function testIpv6IsSupported(): void
    {
        $decision = new IpAccessDecision(['2001:db8::/32'], [], IpAccessDecision::MODE_BLACKLIST);

        $this->assertFalse($decision->evaluate('2001:db8::1')['allowed']);
        $this->assertTrue($decision->evaluate('2001:db9::1')['allowed']);
    }
}
