<?php
/**
 * RbacMiddleware 中间件单元测试
 *
 * 测试中间件的请求处理流程、用户解析、未授权处理。
 */
namespace wise\auth\tests;

use Mockery;
use think\Request;
use wise\auth\middleware\RbacMiddleware;
use wise\auth\exception\UnauthorizedException;

class RbacMiddlewareTest extends TestCase
{
    /** @var RbacMiddleware */
    protected $middleware;

    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new RbacMiddleware();
    }

    // =============================
    // handleUnauthorized 测试
    // =============================

    public function testHandleUnauthorizedJsonAction(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'json');
        $request = new \think\Request();

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Permission denied', 'admin.user.list'
        ]);

        $this->assertNotNull($result);
        $this->assertEquals(403, $result->code());
        $data = $result->getData();
        $this->assertEquals(403, $data['code']);
        $this->assertEquals('Permission denied', $data['msg']);
    }

    public function testHandleUnauthorizedExceptionAction(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'exception');
        $request = Mockery::mock(Request::class);

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Access denied');

        $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Access denied', 'admin.user.create'
        ]);
    }

    public function testHandleUnauthorizedRedirectAction(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'redirect');
        $this->setConfig('wiseauth.unauthorized_redirect', '/admin/login');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Please login', ''
        ]);

        $this->assertNotNull($result);
        $this->assertEquals('/admin/login', $result->getTargetUrl());
        $this->assertEquals(302, $result->code());
    }

    public function testHandleUnauthorizedCustomActionWithClosure(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'custom');
        $this->setConfig('wiseauth.unauthorized_handler', function ($req) {
            return json(['custom' => true], 401);
        });
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Test', ''
        ]);

        $data = $result->getData();
        $this->assertTrue($data['custom']);
    }

    public function testHandleUnauthorizedCustomActionWithClassName(): void
    {
        // 创建一个可 invoke 的类
        $handlerClass = get_class(new class {
            public function __invoke($request) {
                return json(['handler' => 'class_based'], 403);
            }
        });

        $this->setConfig('wiseauth.unauthorized_action', 'custom');
        $this->setConfig('wiseauth.unauthorized_handler', $handlerClass);
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Test', ''
        ]);

        $this->assertNotNull($result);
    }

    public function testHandleUnauthorizedCustomFallbackToJson(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'custom');
        $this->setConfig('wiseauth.unauthorized_handler', null);
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Fallback error', ''
        ]);

        $this->assertEquals(403, $result->code());
        $data = $result->getData();
        $this->assertEquals('Fallback error', $data['msg']);
    }

    public function testHandleUnauthorizedDefaultAction(): void
    {
        $this->setConfig('wiseauth.unauthorized_action', 'unknown_action');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Default fallback', ''
        ]);

        $this->assertEquals(403, $result->code());
    }

    // =============================
    // 场景分离测试（login vs forbidden）
    // =============================

    public function testHandleUnauthorizedLoginReturns401(): void
    {
        $this->setConfig('wise-auth.not_logged_in_action', 'json');
        $this->setConfig('wise-auth.not_logged_in_code', 401);
        $request = new \think\Request();

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Please login first', '', 'login'
        ]);

        $this->assertEquals(401, $result->code());
        $data = $result->getData();
        $this->assertEquals(401, $data['code']);
        $this->assertEquals('Please login first', $data['msg']);
    }

    public function testHandleUnauthorizedForbiddenReturns403(): void
    {
        $this->setConfig('wise-auth.forbidden_action', 'json');
        $this->setConfig('wise-auth.forbidden_code', 403);
        $request = new \think\Request();

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Permission denied: admin.user.list', 'admin.user.list', 'forbidden'
        ]);

        $this->assertEquals(403, $result->code());
        $data = $result->getData();
        $this->assertEquals(403, $data['code']);
    }

    public function testHandleUnauthorizedLoginRedirectUsesCustomUrl(): void
    {
        $this->setConfig('wise-auth.not_logged_in_action', 'redirect');
        $this->setConfig('wise-auth.not_logged_in_redirect', '/admin/login');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Please login', '', 'login'
        ]);

        $this->assertEquals('/admin/login', $result->getTargetUrl());
    }

    public function testHandleUnauthorizedForbiddenRedirectUsesCustomUrl(): void
    {
        $this->setConfig('wise-auth.forbidden_action', 'redirect');
        $this->setConfig('wise-auth.forbidden_redirect', '/admin/403');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Permission denied', '', 'forbidden'
        ]);

        $this->assertEquals('/admin/403', $result->getTargetUrl());
    }

    public function testHandleUnauthorizedLoginFallsBackToLegacyRedirect(): void
    {
        // 新配置为 null，应回退到 unauthorized_redirect
        $this->setConfig('wise-auth.not_logged_in_action', null);
        $this->setConfig('wise-auth.not_logged_in_redirect', null);
        $this->setConfig('wise-auth.unauthorized_action', 'redirect');
        $this->setConfig('wise-auth.unauthorized_redirect', '/admin/login');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Please login', '', 'login'
        ]);

        $this->assertEquals('/admin/login', $result->getTargetUrl());
    }

    public function testHandleUnauthorizedForbiddenFallsBackToLegacyRedirect(): void
    {
        // 新配置为 null，应回退到 unauthorized_redirect
        $this->setConfig('wise-auth.forbidden_action', null);
        $this->setConfig('wise-auth.forbidden_redirect', null);
        $this->setConfig('wise-auth.unauthorized_action', 'redirect');
        $this->setConfig('wise-auth.unauthorized_redirect', '/admin/login');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Permission denied', '', 'forbidden'
        ]);

        $this->assertEquals('/admin/login', $result->getTargetUrl());
    }

    public function testHandleUnauthorizedLoginFallsBackToLegacyJson(): void
    {
        // 新配置为 null，应回退到 unauthorized_action(json) → 但 code 使用 not_logged_in_code
        $this->setConfig('wise-auth.not_logged_in_action', null);
        $this->setConfig('wise-auth.not_logged_in_code', 401);
        $this->setConfig('wise-auth.unauthorized_action', 'json');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Please login', '', 'login'
        ]);

        $this->assertEquals(401, $result->code());
        $data = $result->getData();
        $this->assertEquals(401, $data['code']);
    }

    public function testHandleUnauthorizedCustomHandlerReceivesTypeParameter(): void
    {
        $receivedType = null;
        $this->setConfig('wise-auth.not_logged_in_action', 'custom');
        $this->setConfig('wise-auth.not_logged_in_handler', function ($req, $type) use (&$receivedType) {
            $receivedType = $type;
            return json(['status' => 'ok'], 401);
        });
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Test', '', 'login'
        ]);

        $this->assertEquals('login', $receivedType);
        $this->assertEquals(401, $result->code());
    }

    public function testResolveUnauthorizedActionWithTypeLogin(): void
    {
        $this->setConfig('wise-auth.not_logged_in_action', 'json');
        $request = Mockery::mock(Request::class);

        $action = $this->invokeMethod($this->middleware, 'resolveUnauthorizedAction', [
            $request, 'login'
        ]);

        $this->assertEquals('json', $action);
    }

    public function testResolveUnauthorizedActionWithTypeForbidden(): void
    {
        $this->setConfig('wise-auth.forbidden_action', 'redirect');
        $request = Mockery::mock(Request::class);

        $action = $this->invokeMethod($this->middleware, 'resolveUnauthorizedAction', [
            $request, 'forbidden'
        ]);

        $this->assertEquals('redirect', $action);
    }

    public function testResolveUnauthorizedActionFallbackToLegacyWithTypeLogin(): void
    {
        $this->setConfig('wise-auth.not_logged_in_action', null);
        $this->setConfig('wise-auth.unauthorized_action', 'json');
        $request = Mockery::mock(Request::class);

        $action = $this->invokeMethod($this->middleware, 'resolveUnauthorizedAction', [
            $request, 'login'
        ]);

        $this->assertEquals('json', $action);
    }

    // =============================
    // jsonUnauthorized 测试
    // =============================

    public function testJsonUnauthorizedResponseFormat(): void
    {
        $result = $this->invokeMethod($this->middleware, 'jsonUnauthorized', ['Test error']);
        $data = $result->getData();

        $this->assertArrayHasKey('code', $data);
        $this->assertArrayHasKey('msg', $data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('timestamp', $data);
        $this->assertEquals(403, $data['code']);
        $this->assertEquals('Test error', $data['msg']);
        $this->assertEquals([], $data['data']);
        $this->assertIsInt($data['timestamp']);
    }

    public function testJsonUnauthorizedStatusCode(): void
    {
        $result = $this->invokeMethod($this->middleware, 'jsonUnauthorized', ['Forbidden']);
        $this->assertEquals(403, $result->code());
    }

    // =============================
    // resolveUser 测试
    // =============================

    public function testResolveUserNoSessionOrAuthId(): void
    {
        $this->setConfig('wiseauth.user_resolver', null);
        $this->setConfig('wiseauth.default_user_model', null);
        $request = Mockery::mock(Request::class);
        // auth_user_id 属性不存在 -> null
        $request->shouldReceive('__get')->with('auth_user_id')->andReturn(null);

        $result = $this->invokeMethod($this->middleware, 'resolveUser', [$request]);
        $this->assertNull($result);
    }

    public function testResolveUserWithCustomResolver(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 99]);
        $this->setConfig('wiseauth.user_resolver', function () use ($user) {
            return $user;
        });
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'resolveUser', [$request]);
        $this->assertSame($user, $result);
        $this->assertEquals(99, $result->getAuthIdentifier());
    }

    // =============================
    // shouldBypassAuth 测试
    // =============================

    public function testShouldBypassAuthWhitelistMatch(): void
    {
        $this->setConfig('wiseauth.whitelist_routes', ['/admin/login', '/admin/auth/*']);
        $this->setConfig('wiseauth.blacklist_routes', []);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);
        $manager->shouldReceive('routeMatch')->with('/admin/login', '/admin/login/index')->andReturn(true);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('baseUrl')->andReturn('/admin/login');
        $request->shouldReceive('controller')->andReturn('login');
        $request->shouldReceive('action')->andReturn('index');

        $result = $this->invokeMethod($this->middleware, 'shouldBypassAuth', [$request, $manager]);
        $this->assertTrue($result);
    }

    public function testShouldBypassAuthWhitelistNoMatch(): void
    {
        $this->setConfig('wiseauth.whitelist_routes', ['/admin/login']);
        $this->setConfig('wiseauth.blacklist_routes', []);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);
        // shouldBypassAuth 先匹配 dispatchedRoute，再匹配 baseUrl，两次都返回 false
        $manager->shouldReceive('routeMatch')->andReturn(false);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('baseUrl')->andReturn('/admin/dashboard');
        $request->shouldReceive('controller')->andReturn('dashboard');
        $request->shouldReceive('action')->andReturn('index');

        $result = $this->invokeMethod($this->middleware, 'shouldBypassAuth', [$request, $manager]);
        $this->assertFalse($result);
    }

    public function testShouldBypassAuthBlacklistMatch(): void
    {
        $this->setConfig('wiseauth.whitelist_routes', []);
        $this->setConfig('wiseauth.blacklist_routes', ['/admin/sensitive/*']);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);
        $manager->shouldReceive('routeMatch')->with('/admin/sensitive/*', '/admin/sensitive/data')->andReturn(true);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('baseUrl')->andReturn('/admin/sensitive/data');
        $request->shouldReceive('controller')->andReturn('sensitive');
        $request->shouldReceive('action')->andReturn('data');

        $result = $this->invokeMethod($this->middleware, 'shouldBypassAuth', [$request, $manager]);
        $this->assertFalse($result);
    }

    public function testShouldBypassAuthEmptyLists(): void
    {
        $this->setConfig('wiseauth.whitelist_routes', []);
        $this->setConfig('wiseauth.blacklist_routes', []);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('baseUrl')->andReturn('/admin/dashboard');
        $request->shouldReceive('controller')->andReturn('dashboard');
        $request->shouldReceive('action')->andReturn('index');

        $result = $this->invokeMethod($this->middleware, 'shouldBypassAuth', [$request, $manager]);
        $this->assertFalse($result);
    }

    // =============================
    // 中间件属性测试
    // =============================

    public function testMiddlewareClassExists(): void
    {
        $this->assertInstanceOf(RbacMiddleware::class, $this->middleware);
    }

    public function testMiddlewareHandleMethodExists(): void
    {
        $this->assertTrue(method_exists($this->middleware, 'handle'));
    }
}
