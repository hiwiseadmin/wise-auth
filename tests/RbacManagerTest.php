<?php
/**
 * RbacManager 核心服务单元测试
 *
 * 测试权限检查、角色树构建、路由匹配、缓存管理、角色继承展开、约束检查。
 */
namespace wise\auth\tests;

use Mockery;
use wise\auth\service\RbacManager;
use wise\auth\exception\ConstraintViolationException;

class RbacManagerTest extends TestCase
{
    /** @var RbacManager */
    protected $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setConfig('wise-auth.cache_enabled', false);
        $this->manager = new RbacManager();
    }


    public function testIsSuperAdminBySuperAdminIds(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', [1, 2, 3]);
        $this->setConfig('wise-auth.super_role', null);
        $this->assertTrue($this->manager->isSuperAdmin(1, 'admin'));
        $this->assertTrue($this->manager->isSuperAdmin(2, 'admin'));
        $this->assertTrue($this->manager->isSuperAdmin(3, 'admin'));
        $this->assertFalse($this->manager->isSuperAdmin(4, 'admin'));
        $this->assertFalse($this->manager->isSuperAdmin(99, 'admin'));
    }

    public function testIsSuperAdminEmptySuperAdminIds(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', []);
        $this->setConfig('wise-auth.super_role', null);
        $this->assertFalse($this->manager->isSuperAdmin(1, 'admin'));
    }

    public function testIsSuperAdminWithStringId(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', ['abc', 'xyz']);
        $this->setConfig('wise-auth.super_role', null);
        $this->assertTrue($this->manager->isSuperAdmin('abc', 'custom'));
        $this->assertFalse($this->manager->isSuperAdmin('def', 'custom'));
    }

    public function testIsSuperAdminDefaultUserType(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', [1]);
        $this->assertTrue($this->manager->isSuperAdmin(1));
    }

    public function testIsSuperAdminDisabledSuperRole(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', []);
        $this->setConfig('wise-auth.super_role', null);
        $this->assertFalse($this->manager->isSuperAdmin(1, 'admin'));
    }


    public function testRouteMatchExact(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/user/list', '/admin/user/list'));
    }

    public function testRouteMatchNoMatch(): void
    {
        $this->assertFalse($this->manager->routeMatch('/admin/user/list', '/admin/role/list'));
    }

    public function testRouteMatchWildcardStar(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/user/*', '/admin/user/list'));
        $this->assertTrue($this->manager->routeMatch('/admin/user/*', '/admin/user/create'));
        $this->assertTrue($this->manager->routeMatch('/admin/user/*', '/admin/user/delete/123'));
    }

    public function testRouteMatchWildcardAtRoot(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/*', '/admin/anything/here'));
        $this->assertTrue($this->manager->routeMatch('/admin/*', '/admin/'));
    }

    public function testRouteMatchWildcardDoesNotCrossBoundary(): void
    {
        $result = $this->manager->routeMatch('/admin/*', '/api/something');
        $this->assertFalse($result);
    }

    public function testRouteMatchSpecialRegexChars(): void
    {
        $this->assertFalse($this->manager->routeMatch('/admin/user.list', '/admin/userXlist'));
        $this->assertTrue($this->manager->routeMatch('/admin/user.list', '/admin/user.list'));
    }

    public function testRouteMatchEmptyPattern(): void
    {
        $this->assertTrue($this->manager->routeMatch('', ''));
        $this->assertFalse($this->manager->routeMatch('', '/some/route'));
    }

    public function testRouteMatchComplexPattern(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/*/edit/*', '/admin/user/edit/123'));
        $this->assertTrue($this->manager->routeMatch('/admin/*/edit/*', '/admin/role/edit/abc'));
        $this->assertFalse($this->manager->routeMatch('/admin/*/view/*', '/admin/user/edit/123'));
    }


    public function testRouteMatchIgnoresLeadingSlashOnBothSides(): void
    {
        $this->assertTrue($this->manager->routeMatch('/plugin/foo/index', 'plugin/foo/index'));
        $this->assertTrue($this->manager->routeMatch('plugin/foo/index', '/plugin/foo/index'));
        $this->assertTrue($this->manager->routeMatch('plugin/foo/index', 'plugin/foo/index'));
    }

    public function testRouteMatchNormalizesBeforeWildcardMatch(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/search/*', 'admin/search/global'));
        $this->assertTrue($this->manager->routeMatch('admin/search/*', '/admin/search/global'));
        $this->assertFalse($this->manager->routeMatch('admin/search/*', '/admin/menu/index'));
    }

    public function testRouteMatchKeepsTrailingSlashSemanticsAfterNormalize(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/*', '/admin/'));
        $this->assertFalse($this->manager->routeMatch('/admin/*', '/api/'));
    }

    public function testRouteMatchNormalizationDoesNotCauseFalsePositive(): void
    {
        $this->assertFalse($this->manager->routeMatch('/plugin/aaa/index', 'plugin/bbb/index'));
        $this->assertFalse($this->manager->routeMatch('/403.html', '/admin/login'));
    }


    public function testRouteMatchAllowsTrailingPathParams(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/menu/edit', '/admin/menu/edit/id/2'));
        $this->assertTrue($this->manager->routeMatch('/admin/admin/edit', '/admin/admin/edit/id/2'));
        $this->assertTrue($this->manager->routeMatch('/admin/plugin/configIndex/name/wisecms', '/admin/plugin/configIndex/name/wisecms'));
        $this->assertTrue($this->manager->routeMatch('/admin/menu/edit', '/admin/menu/edit/id/2/'));
    }

    public function testRouteMatchTrailingParamsDoNotSwallowSiblingActions(): void
    {
        $this->assertFalse($this->manager->routeMatch('/admin/menu', '/admin/menu/edit/id/2'));
        $this->assertFalse($this->manager->routeMatch('/admin/menu/edit', '/admin/menu/update'));
    }

    public function testRouteMatchWhitelistPatternsFromConfig(): void
    {
        $this->assertTrue($this->manager->routeMatch('/admin/login/*', '/admin/login/doLogin'));
        $this->assertTrue($this->manager->routeMatch('/admin/index/lockscreen', '/admin/index/lockscreen'));
        $this->assertFalse($this->manager->routeMatch('/admin/index/lockscreen', '/admin/index/index'));
    }


    public function testMethodMatchWildcard(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['*', 'GET']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['*', 'POST']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['*', 'DELETE']));
    }

    public function testMethodMatchAny(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['ANY', 'GET']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['ANY', 'POST']));
    }

    public function testMethodMatchExactSingle(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET', 'GET']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['POST', 'POST']));
        $this->assertFalse($this->invokeMethod($this->manager, 'methodMatch', ['GET', 'POST']));
    }

    public function testMethodMatchMultiple(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET,POST', 'GET']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET,POST', 'POST']));
        $this->assertFalse($this->invokeMethod($this->manager, 'methodMatch', ['GET,POST', 'DELETE']));
    }

    public function testMethodMatchCaseInsensitive(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['get', 'GET']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET', 'get']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['post,get', 'GET']));
    }

    public function testMethodMatchWithSpaces(): void
    {
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET, POST', 'POST']));
        $this->assertTrue($this->invokeMethod($this->manager, 'methodMatch', ['GET ,POST', 'GET']));
    }


    public function testBuildTreeEmptyArray(): void
    {
        $result = $this->manager->buildTree([]);
        $this->assertEquals([], $result);
    }

    public function testBuildTreeSingleItem(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Root', 'parent_id' => 0],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(1, $result);
        $this->assertEquals('Root', $result[0]['name']);
    }

    public function testBuildTreeTwoLevels(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Parent', 'parent_id' => 0],
            ['id' => 2, 'name' => 'Child', 'parent_id' => 1],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(1, $result);
        $this->assertEquals('Parent', $result[0]['name']);
        $this->assertCount(1, $result[0]['children']);
        $this->assertEquals('Child', $result[0]['children'][0]['name']);
    }

    public function testBuildTreeThreeLevels(): void
    {
        $items = [
            ['id' => 1, 'name' => 'L1', 'parent_id' => 0],
            ['id' => 2, 'name' => 'L2', 'parent_id' => 1],
            ['id' => 3, 'name' => 'L3', 'parent_id' => 2],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(1, $result);
        $this->assertCount(1, $result[0]['children']);
        $this->assertCount(1, $result[0]['children'][0]['children']);
        $this->assertEquals('L3', $result[0]['children'][0]['children'][0]['name']);
    }

    public function testBuildTreeMultipleRoots(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Root A', 'parent_id' => 0],
            ['id' => 2, 'name' => 'Root B', 'parent_id' => 0],
            ['id' => 3, 'name' => 'Child A1', 'parent_id' => 1],
            ['id' => 4, 'name' => 'Child B1', 'parent_id' => 2],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(2, $result);
        $this->assertEquals('Root A', $result[0]['name']);
        $this->assertEquals('Root B', $result[1]['name']);
        $this->assertCount(1, $result[0]['children']);
        $this->assertCount(1, $result[1]['children']);
    }

    public function testBuildTreeOrphanNodes(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Root', 'parent_id' => 0],
            ['id' => 2, 'name' => 'Orphan', 'parent_id' => 99],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(1, $result);
        $this->assertEquals('Root', $result[0]['name']);
    }

    public function testBuildTreePreservesItemData(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Root', 'parent_id' => 0, 'extra' => 'value'],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertEquals('value', $result[0]['extra']);
    }

    public function testBuildTreeNoParentIdKey(): void
    {
        $items = [
            ['id' => 1, 'name' => 'Root'],
        ];
        $result = $this->manager->buildTree($items);
        $this->assertCount(1, $result);
        $this->assertEquals('Root', $result[0]['name']);
    }


    public function testExpandRoleIdsDisabledInheritance(): void
    {
        $this->setConfig('wise-auth.inheritance_enabled', false);
        $result = $this->invokeMethod($this->manager, 'expandRoleIdsWithInheritance', [[1, 2, 3]]);
        $this->assertEquals([1, 2, 3], $result);
    }

    public function testExpandRoleIdsEmptyInput(): void
    {
        $result = $this->invokeMethod($this->manager, 'expandRoleIdsWithInheritance', [[]]);
        $this->assertEquals([], $result);
    }


    public function testManagerUsesCacheKeyHelper(): void
    {
        $traits = class_uses($this->manager);
        $this->assertArrayHasKey(\wise\auth\traits\CacheKeyHelper::class, $traits);
    }

    public function testManagerGetCacheKey(): void
    {
        $key = $this->invokeMethod($this->manager, 'getCacheKey', ['test']);
        $this->assertIsString($key);
        $this->assertStringStartsWith('wiseauth:', $key);
    }


    public function testConstraintEngineBeforeAssignRoleWithoutArgsPasses(): void
    {
        $this->setConfig('wise-auth.constraints', []);

        $engine = new \wise\auth\service\ConstraintEngine();

        $this->assertTrue($engine->checkBuiltinConstraints('beforeAssignRole'));
    }

    public function testConstraintEngineUnknownMethodPasses(): void
    {
        $this->setConfig('wise-auth.constraints', ['mutual_exclusion' => []]);

        $engine = new \wise\auth\service\ConstraintEngine();

        $this->assertTrue($engine->checkBuiltinConstraints('unknownMethod'));
    }

    public function testConstraintEngineSaveRoleConstraintsWithEmptyConfigPasses(): void
    {
        $this->setConfig('wise-auth.constraints', ['mutual_exclusion' => [['a', 'b']]]);

        $engine = new \wise\auth\service\ConstraintEngine();

        $this->assertTrue($engine->checkSaveRoleConstraints([]));
    }


    public function testManagerDelegatesConstraintCheckToEngine(): void
    {
        $this->setConfig('wise-auth.constraints', []);
        app()->bind(\wise\auth\service\ConstraintEngine::class, new \wise\auth\service\ConstraintEngine());

        $this->assertTrue($this->manager->checkConstraint('unknownMethod'));
    }

    public function testCustomConstraintCheckerIsInvoked(): void
    {
        $called = [];

        $this->setConfig('wise-auth.constraint_checker', function (string $method, array $payload) use (&$called): bool {
            $called[] = $method;

            return true;
        });
        app()->bind(\wise\auth\service\ConstraintEngine::class, new \wise\auth\service\ConstraintEngine());

        $this->assertTrue($this->manager->checkConstraint('beforeAssignRole', 1, 'admin', 2));
        $this->assertSame(['beforeAssignRole'], $called, '自定义约束检查器应收到去前缀的方法名');
    }


    public function testSuperAdminIdsMixedTypes(): void
    {
        $this->setConfig('wise-auth.super_admin_ids', [1, '2', 3]);
        $this->assertTrue($this->manager->isSuperAdmin(1, 'admin'));
        $this->assertTrue($this->manager->isSuperAdmin('2', 'admin'));
    }

    public function testRouteMatchSlashes(): void
    {
        $this->assertTrue($this->manager->routeMatch('/', '/'));
        $this->assertFalse($this->manager->routeMatch('/', '/admin'));
    }

    public function testRouteMatchWildcardOnly(): void
    {
        $this->assertTrue($this->manager->routeMatch('*', '/any/route/here'));
        $this->assertTrue($this->manager->routeMatch('*', '/'));
    }
}
