<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use think\Request;
use wise\login\action\SameOriginCheckAction;
use wise\login\contract\LoginPayload;

/**
 * 同源校验 Action 单元测试（登录端点来源校验）
 *
 * 口径：只拒绝「证据明确为恶意/异常」的请求；证据缺失（三个头全空）默认放行，
 * 由 CsrfTokenMiddleware 兜底。
 *
 * 判定走 evaluate()，避免依赖 JsonResponse 的容器渲染；
 * handle() 仅验证放行/跳过路径。
 */
class SameOriginCheckTest extends TestCase
{
    private const HOST   = 'admin.example.com';
    private const ORIGIN = 'https://admin.example.com';

    public function testReadOnlyRequestIsSkipped(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('GET', ['Origin' => 'https://evil.example.org']));

        $this->assertSame('skipped', $result['status']);
        $this->assertTrue($result['allowed']);
    }

    public function testSameOriginPostPasses(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Origin' => self::ORIGIN]));

        $this->assertSame('passed', $result['status']);
        $this->assertTrue($result['allowed']);
    }

    public function testCrossOriginPostIsBlocked(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Origin' => 'https://evil.example.org']));

        $this->assertSame('blocked', $result['status']);
        $this->assertFalse($result['allowed']);
    }

    public function testMissingSourcePassesByDefault(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', []));

        $this->assertSame('passed', $result['status']);
        $this->assertTrue($result['allowed']);
    }

    public function testMissingSourceIsBlockedInStrictMode(): void
    {
        $action = new SameOriginCheckAction([], true);

        $result = $action->evaluate($this->request('POST', []));

        $this->assertSame('blocked', $result['status']);
        $this->assertFalse($result['allowed']);
    }

    public function testRefererIsUsedWhenOriginMissing(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Referer' => self::ORIGIN . '/admin/login']));

        $this->assertTrue($result['allowed']);
    }

    public function testCrossOriginRefererIsBlocked(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Referer' => 'https://evil.example.org/phish']));

        $this->assertFalse($result['allowed']);
    }

    public function testSecFetchSiteCrossSiteIsBlockedEvenWithValidOrigin(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', [
                'Origin'        => self::ORIGIN,
                'Sec-Fetch-Site' => 'cross-site',
            ]));

        $this->assertSame('blocked', $result['status']);
    }

    public function testSecFetchSiteSameSiteIsBlockedByDefault(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', [
                'Origin'        => 'https://sibling.example.com',
                'Sec-Fetch-Site' => 'same-site',
            ]));

        $this->assertSame('blocked', $result['status']);
    }

    public function testSecFetchSiteSameSiteAllowedWhenRelaxed(): void
    {
        $action = new SameOriginCheckAction(['sibling.example.com'], true, false);

        $result = $action->evaluate($this->request('POST', [
            'Origin'        => 'https://sibling.example.com',
            'Sec-Fetch-Site' => 'same-site',
        ]));

        $this->assertTrue($result['allowed']);
    }

    public function testExplicitAllowedHostsAreHonoured(): void
    {
        $action = new SameOriginCheckAction(['admin.example.com']);

        $this->assertTrue(
            $action->evaluate($this->request('POST', ['Origin' => self::ORIGIN]))['allowed']
        );
    }

    public function testPortIsIgnoredInComparison(): void
    {
        $action = new SameOriginCheckAction(['admin.example.com']);

        $this->assertTrue(
            $action->evaluate($this->request('POST', ['Origin' => 'https://admin.example.com:8443']))['allowed']
        );
    }

    public function testHostHeaderImpersonationIsBlockedWhenAllowedHostsConfigured(): void
    {
        $action = new SameOriginCheckAction(['admin.example.com']);

        $result = $action->evaluate(
            $this->request('POST', ['Origin' => 'https://evil.example.org'], 'evil.example.org')
        );

        $this->assertFalse($result['allowed']);
    }

    public function testPrivacyOriginNullIsBlockedEvenWhenRelaxed(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Origin' => 'null']));

        $this->assertSame('blocked', $result['status']);
    }

    public function testMissingSourcePassesWithSameOriginFetchMetadata(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', ['Sec-Fetch-Site' => 'same-origin']));

        $this->assertSame('passed', $result['status']);
        $this->assertTrue($result['allowed']);
    }

    public function testFetchMetadataDoesNotRescueCrossOriginSource(): void
    {
        $result = (new SameOriginCheckAction())
            ->evaluate($this->request('POST', [
                'Origin'         => 'https://evil.example.org',
                'Sec-Fetch-Site' => 'same-origin',
            ]));

        $this->assertSame('blocked', $result['status']);
    }

    public function testFetchMetadataTrustCanBeDisabled(): void
    {
        $action = new SameOriginCheckAction([], true, true, false);

        $result = $action->evaluate($this->request('POST', ['Sec-Fetch-Site' => 'same-origin']));

        $this->assertSame('blocked', $result['status']);
    }

    public function testHandlePassesThroughOnSameOrigin(): void
    {
        $payload = new LoginPayload(
            $this->request('POST', ['Origin' => self::ORIGIN]),
            'admin',
            '127.0.0.1'
        );

        $this->assertSame('passed', (new SameOriginCheckAction())->handle($payload, fn($p) => 'passed'));
        $this->assertSame('passed', $payload->pipeLog[0]['status']);
    }


    private function request(string $method, array $headers, string $host = self::HOST): Request
    {
        $request = new Request();

        $request->setMethod($method);
        $request->setHost($host);
        $request->withHeader($headers);
        $request->withServer([
            'REQUEST_METHOD' => $method,
            'HTTP_HOST'      => $host,
            'SERVER_NAME'    => $host,
            'SERVER_PORT'    => '443',
            'REQUEST_SCHEME' => 'https',
            'HTTPS'          => 'on',
        ]);

        return $request;
    }
}
