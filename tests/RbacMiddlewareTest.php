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


    public function testHandleUnauthorizedJsonAction(): void
    {
        $this->setConfig('wise-auth.unauthorized_action', 'json');
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
        $this->setConfig('wise-auth.unauthorized_action', 'exception');
        $request = Mockery::mock(Request::class);

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Access denied');

        $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Access denied', 'admin.user.create'
        ]);
    }

    public function testHandleUnauthorizedRedirectAction(): void
    {
        $this->setConfig('wise-auth.unauthorized_action', 'redirect');
        $this->setConfig('wise-auth.unauthorized_redirect', '/admin/login');
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
        $this->setConfig('wise-auth.unauthorized_action', 'custom');
        $this->setConfig('wise-auth.unauthorized_handler', function ($req) {
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
        $handlerClass = get_class(new class {
            public function __invoke($request) {
                return json(['handler' => 'class_based'], 403);
            }
        });

        $this->setConfig('wise-auth.unauthorized_action', 'custom');
        $this->setConfig('wise-auth.unauthorized_handler', $handlerClass);
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Test', ''
        ]);

        $this->assertNotNull($result);
    }

    public function testHandleUnauthorizedCustomFallbackToJson(): void
    {
        $this->setConfig('wise-auth.unauthorized_action', 'custom');
        $this->setConfig('wise-auth.unauthorized_handler', null);
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
        $this->setConfig('wise-auth.unauthorized_action', 'unknown_action');
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'handleUnauthorized', [
            $request, 'Default fallback', ''
        ]);

        $this->assertEquals(403, $result->code());
    }


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


    public function testResolveUserNoSessionOrAuthId(): void
    {
        $this->setConfig('wise-auth.user_resolver', null);
        $this->setConfig('wise-auth.default_user_model', null);
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('__get')->with('auth_user_id')->andReturn(null);

        $result = $this->invokeMethod($this->middleware, 'resolveUser', [$request]);
        $this->assertNull($result);
    }

    public function testResolveUserWithCustomResolver(): void
    {
        $user = new \wise\auth\tests\stubs\TestUser(['id' => 99]);
        $this->setConfig('wise-auth.user_resolver', function () use ($user) {
            return $user;
        });
        $request = Mockery::mock(Request::class);

        $result = $this->invokeMethod($this->middleware, 'resolveUser', [$request]);
        $this->assertSame($user, $result);
        $this->assertEquals(99, $result->getAuthIdentifier());
    }


    public function testShouldBypassAuthWhitelistMatch(): void
    {
        $this->setConfig('wise-auth.whitelist_routes', ['/admin/login', '/admin/auth/*']);
        $this->setConfig('wise-auth.blacklist_routes', []);

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
        $this->setConfig('wise-auth.whitelist_routes', ['/admin/login']);
        $this->setConfig('wise-auth.blacklist_routes', []);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);
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
        $this->setConfig('wise-auth.whitelist_routes', []);
        $this->setConfig('wise-auth.blacklist_routes', ['/admin/sensitive/*']);

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
        $this->setConfig('wise-auth.whitelist_routes', []);
        $this->setConfig('wise-auth.blacklist_routes', []);

        $manager = Mockery::mock(\wise\auth\service\RbacManager::class);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('baseUrl')->andReturn('/admin/dashboard');
        $request->shouldReceive('controller')->andReturn('dashboard');
        $request->shouldReceive('action')->andReturn('index');

        $result = $this->invokeMethod($this->middleware, 'shouldBypassAuth', [$request, $manager]);
        $this->assertFalse($result);
    }


    /**
     * 应用级中间件早于路由分派执行：controller/action 仍是空串，
     * 必须回退到 URL 路径，否则会拼出 '/admin//'（权限永远匹配不上，
     * 白名单模式下非超管被全量拒绝）。
     */
    public function testGetDispatchedRouteFallsBackToUrlBeforeDispatch(): void
    {
        $request = new \think\Request();
        $request->setPathinfo('member/level/index');

        $this->assertSame('', $request->controller(), '分派前 controller 应为空');
        $this->assertSame('', $request->action(), '分派前 action 应为空');
        $this->assertSame(
            '/admin/member/level/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /** pathinfo 未剥离应用名首段时，不应拼成 /admin/admin/... */
    /**
     * 多应用模式：think-multi-app 已把应用名首段剥离（root=/admin、pathinfo=member/level/index），
     * 此时不能再剥一次。
     */
    public function testGetDispatchedRouteWithAppRoot(): void
    {
        $request = new \think\Request();
        $request->setRoot('/admin');
        $request->setPathinfo('member/level/index');

        $this->assertSame(
            '/admin/member/level/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /**
     * 回归守卫：控制器名与应用名相同（/admin/admin/getList）时不得把 admin 当应用名剥掉，
     * 否则路由变成 /admin/getList，匹配不到权限节点 → 非超管恒 403。
     */
    public function testGetDispatchedRouteKeepsControllerNamedLikeApp(): void
    {
        $request = new \think\Request();
        $request->setRoot('/admin');
        $request->setPathinfo('admin/getList');

        $this->assertSame(
            '/admin/admin/getList',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /**
     * 自定义入口（root 不是 /{app}）：pathinfo 里仍带应用名，需要剥一次。
     */
    public function testGetDispatchedRouteStripsAppNameForCustomEntry(): void
    {
        $request = new \think\Request();
        $request->setRoot('/custom');
        $request->setPathinfo('admin/member/index');

        $this->assertSame(
            '/admin/member/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /** 带伪静态后缀时去掉后缀，与菜单 path 写法一致 */
    public function testGetDispatchedRouteStripsUrlSuffix(): void
    {
        $request = new \think\Request();
        $request->setPathinfo('wise_config/index.html');

        $this->assertSame(
            '/admin/wise_config/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /** 直接访问应用根（/admin）时按默认控制器/操作补全 */
    public function testGetDispatchedRouteDefaultsForAppRoot(): void
    {
        $request = new \think\Request();
        $request->setPathinfo('');

        $this->assertSame(
            '/admin/index/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }

    /** 分派后（controller/action 已写入）仍用 controller/action 形态 */
    public function testGetDispatchedRouteUsesControllerAfterDispatch(): void
    {
        $request = new \think\Request();
        $request->setPathinfo('member/level/index');
        $request->setController('Level');
        $request->setAction('index');

        $this->assertSame(
            '/admin/level/index',
            $this->invokeMethod($this->middleware, 'getDispatchedRoute', [$request])
        );
    }


    public function testMiddlewareClassExists(): void
    {
        $this->assertInstanceOf(RbacMiddleware::class, $this->middleware);
    }

    public function testMiddlewareHandleMethodExists(): void
    {
        $this->assertTrue(method_exists($this->middleware, 'handle'));
    }
}
