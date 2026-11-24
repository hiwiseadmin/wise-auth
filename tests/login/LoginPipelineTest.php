<?php
declare(strict_types=1);

namespace wise\login\test;

use PHPUnit\Framework\TestCase;
use think\Request;
use think\Response;
use wise\login\action\IpGuardAction;
use wise\login\action\LockCheckAction;
use wise\login\action\CaptchaCheckAction;
use wise\login\action\FailureRecordAction;
use wise\login\action\SuccessRecordAction;
use wise\login\action\DeviceRecordAction;
use wise\login\action\AnomalyDetectAction;
use wise\login\contract\LoginPayload;
use wise\login\contract\LoginResultPayload;
use wise\login\contract\LoginGuardAction;
use wise\login\contract\LoginResultAction;
use wise\login\LoginPipeline;
use wise\login\LoginRegistry;

/**
 * 登录安全 Pipeline 单元测试（V2 新增）
 *
 * 覆盖：
 * - 3 个守卫 Action 独立测试
 * - 4 个结果 Action 独立测试
 * - LoginPipeline 编排测试
 * - 插件注册测试
 */
class LoginPipelineTest extends TestCase
{
    protected function setUp(): void
    {
        LoginRegistry::clear();
        parent::setUp();
        \wise_auth_test_reset();
    }

    protected function tearDown(): void
    {
        LoginRegistry::clear();
    }


    public function testIpGuardBlocksBlacklistedIp(): void
    {
        $action = new IpGuardAction(['192.168.0.0/16'], [], 'blacklist');
        $request = $this->createMockRequest('192.168.1.100');
        $payload = new LoginPayload($request, 'admin', '192.168.1.100');

        $next = function ($p) { return 'passed'; };
        $result = $action->handle($payload, $next);

        $this->assertInstanceOf(Response::class, $result);
        $this->assertStringContainsString('黑名单', $result->getContent());
    }

    public function testIpGuardPassesCleanIp(): void
    {
        $action = new IpGuardAction(['192.168.0.0/16'], ['10.0.0.0/8'], 'blacklist');
        $request = $this->createMockRequest('10.0.0.1');
        $payload = new LoginPayload($request, 'admin', '10.0.0.1');

        $next = function ($p) { return 'passed'; };
        $result = $action->handle($payload, $next);

        $this->assertSame('passed', $result);
    }

    public function testIpGuardWhitelistModeBlocksNonWhitelisted(): void
    {
        $action = new IpGuardAction([], ['192.168.1.0/24'], 'whitelist');
        $request = $this->createMockRequest('10.0.0.1');
        $payload = new LoginPayload($request, 'admin', '10.0.0.1');

        $next = function ($p) { return 'passed'; };
        $result = $action->handle($payload, $next);

        $this->assertInstanceOf(Response::class, $result);
        $this->assertStringContainsString('不在白名单', $result->getContent());
    }


    public function testFailureRecordSkipsOnSuccess(): void
    {
        $action = new FailureRecordAction();
        $request = $this->createMockRequest('127.0.0.1');
        $response = new \WiseAuthTestResponse();
        $payload = new LoginResultPayload($request, $response, [], true, [
            'actions' => ['failure_lock' => true, 'failure_event' => true, 'lock_notify' => true],
        ]);
        $payload->username = 'admin';

        $next = fn($p) => $p;
        $result = $action->handle($payload, $next);

        $this->assertTrue($result->isSuccess);
    }

    public function testFailureRecordExecutesOnFailure(): void
    {
        $action = new FailureRecordAction();
        $request = $this->createMockRequest('127.0.0.1');
        $response = new \WiseAuthTestResponse();
        $payload = new LoginResultPayload($request, $response, [], false, [
            'actions' => ['failure_lock' => true, 'failure_event' => true, 'lock_notify' => false],
        ]);
        $payload->username = 'admin';

        $next = fn($p) => $p;
        $result = $action->handle($payload, $next);

        $this->assertFalse($result->isSuccess);
    }


    public function testSuccessRecordSkipsOnFailure(): void
    {
        $action = new SuccessRecordAction();
        $request = $this->createMockRequest('127.0.0.1');
        $response = new \WiseAuthTestResponse();
        $payload = new LoginResultPayload($request, $response, [], false, [
            'actions' => ['success_clear' => true, 'success_event' => true],
        ]);

        $next = fn($p) => $p;
        $result = $action->handle($payload, $next);
        $this->assertFalse($result->isSuccess);
    }


    public function testPipelineExecutesGuardActionsInOrder(): void
    {
        $order = [];

        $pipe1 = new class($order) implements LoginGuardAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginPayload $payload, \Closure $next) {
                $this->order[] = 1;
                return $next($payload);
            }
        };

        $pipe2 = new class($order) implements LoginGuardAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginPayload $payload, \Closure $next) {
                $this->order[] = 2;
                return $next($payload);
            }
        };

        $request = $this->createMockRequest('127.0.0.1');
        $payload = new LoginPayload($request, 'admin', '127.0.0.1');

        $pipeline = new LoginPipeline();
        $result = $pipeline
            ->through([$pipe1, $pipe2])
            ->guardThen($payload, function ($p) { return 'done'; });

        $this->assertSame('done', $result);
        $this->assertSame([1, 2], $order);
    }

    public function testPipelineStopsOnGuardInterception(): void
    {
        $order = [];

        $blocker = new class($order) implements LoginGuardAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginPayload $payload, \Closure $next) {
                $this->order[] = 'block';
                return json(['code' => 403, 'msg' => 'Blocked', 'data' => [], 'timestamp' => time()]);
            }
        };

        $neverRun = new class($order) implements LoginGuardAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginPayload $payload, \Closure $next) {
                $this->order[] = 'never';
                return $next($payload);
            }
        };

        $request = $this->createMockRequest('127.0.0.1');
        $payload = new LoginPayload($request, 'admin', '127.0.0.1');

        $pipeline = new LoginPipeline();
        $result = $pipeline
            ->through([$blocker, $neverRun])
            ->guardThen($payload, function ($p) { return 'done'; });

        $this->assertInstanceOf(Response::class, $result);
        $this->assertSame(['block'], $order);
    }

    public function testResultPipelineExecutesInOrder(): void
    {
        $order = [];

        $a1 = new class($order) implements LoginResultAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginResultPayload $payload, \Closure $next): LoginResultPayload {
                $this->order[] = 'a1';
                return $next($payload);
            }
        };

        $a2 = new class($order) implements LoginResultAction {
            private $order;
            public function __construct(&$order) { $this->order = &$order; }
            public function handle(LoginResultPayload $payload, \Closure $next): LoginResultPayload {
                $this->order[] = 'a2';
                return $next($payload);
            }
        };

        $request = $this->createMockRequest('127.0.0.1');
        $response = new \WiseAuthTestResponse();
        $payload = new LoginResultPayload($request, $response, [], true);

        $pipeline = new LoginPipeline();
        $result = $pipeline
            ->through([$a1, $a2])
            ->resultThen($payload, fn($p) => $p);

        $this->assertSame(['a1', 'a2'], $order);
        $this->assertTrue($result->isSuccess);
    }


    public function testRegisterGuardAction(): void
    {
        LoginRegistry::registerGuard('App\\Custom\\SlaCheckAction');
        $actions = LoginRegistry::getGuardActions();

        $this->assertCount(1, $actions);
        $this->assertSame('App\\Custom\\SlaCheckAction', $actions[0]);
    }

    public function testRegisterResultAction(): void
    {
        LoginRegistry::registerResultAction('App\\Custom\\SyncAction');
        $actions = LoginRegistry::getResultActions();

        $this->assertCount(1, $actions);
        $this->assertSame('App\\Custom\\SyncAction', $actions[0]);
    }

    public function testClearRemovesAllRegistrations(): void
    {
        LoginRegistry::registerGuard('Pipe1');
        LoginRegistry::registerResultAction('Pipe2');
        LoginRegistry::clear();

        $this->assertEmpty(LoginRegistry::getGuardActions());
        $this->assertEmpty(LoginRegistry::getResultActions());
    }


    public function testLoginPayloadLogs(): void
    {
        $request = $this->createMockRequest('127.0.0.1');
        $payload = new LoginPayload($request, 'admin', '127.0.0.1');

        $payload->log('TestAction', 'passed', 'OK');

        $this->assertCount(1, $payload->pipeLog);
        $this->assertSame('TestAction', $payload->pipeLog[0]['action']);
        $this->assertSame('passed', $payload->pipeLog[0]['status']);
    }


    public function testLoginResultPayloadActionEnabled(): void
    {
        $request = $this->createMockRequest('127.0.0.1');
        $response = new \WiseAuthTestResponse();
        $payload = new LoginResultPayload($request, $response, [], false, [
            'actions' => ['failure_lock' => true, 'failure_event' => false],
        ]);

        $this->assertTrue($payload->actionEnabled('failure_lock'));
        $this->assertFalse($payload->actionEnabled('failure_event'));
        $this->assertFalse($payload->actionEnabled('non_existent'));
    }


    private function createMockRequest(string $ip): Request
    {
        return (new Request())->withServer(['REMOTE_ADDR' => $ip]);
    }
}
