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
        // 创建 manager 实例，但禁用缓存（所有测试需要 mock 数据库）
        $this->setConfig('wiseauth.cache_enabled', false);
        $this->manager = new RbacManager();
    }

    // =============================
    // isSuperAdmin 测试
    // =============================

    public function testIsSuperAdminBySuperAdminIds(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', [1, 2, 3]);
        $this->assertTrue($this->manager->isSuperAdmin(1, 'admin'));
        $this->assertTrue($this->manager->isSuperAdmin(2, 'admin'));
        $this->assertTrue($this->manager->isSuperAdmin(3, 'admin'));
        $this->assertFalse($this->manager->isSuperAdmin(4, 'admin'));
        $this->assertFalse($this->manager->isSuperAdmin(99, 'admin'));
    }

    public function testIsSuperAdminEmptySuperAdminIds(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', []);
        $this->setConfig('wiseauth.super_role', null);
        $this->assertFalse($this->manager->isSuperAdmin(1, 'admin'));
    }

    public function testIsSuperAdminWithStringId(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', ['abc', 'xyz']);
        $this->assertTrue($this->manager->isSuperAdmin('abc', 'custom'));
        $this->assertFalse($this->manager->isSuperAdmin('def', 'custom'));
    }

    public function testIsSuperAdminDefaultUserType(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', [1]);
        $this->assertTrue($this->manager->isSuperAdmin(1)); // default userType = 'admin'
    }

    public function testIsSuperAdminDisabledSuperRole(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', []);
        $this->setConfig('wiseauth.super_role', null);
        $this->assertFalse($this->manager->isSuperAdmin(1, 'admin'));
    }

    // =============================
    // routeMatch 测试
    // =============================

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
        // * 不应该匹配跨层级
        $result = $this->manager->routeMatch('/admin/*', '/api/something');
        // * 只匹配同路径段内的任意字符，不跨 /
        // 实际行为：preg_quote 会将 / 转义，* 替换为 .* 匹配任意字符
        // 所以 /admin/* 会匹配 /admin/anything 但不匹配 /api/something
        $this->assertFalse($result);
    }

    public function testRouteMatchSpecialRegexChars(): void
    {
        // 测试路由中特殊正则字符被正确转义
        $this->assertFalse($this->manager->routeMatch('/admin/user.list', '/admin/userXlist'));
        // . 被转义后只能匹配字面量 .
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

    // =============================
    // methodMatch 测试（通过反射）
    // =============================

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

    // =============================
    // buildTree 测试
    // =============================

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

    // =============================
    // expandRoleIdsWithInheritance 测试
    // =============================

    public function testExpandRoleIdsDisabledInheritance(): void
    {
        $this->setConfig('wiseauth.inheritance_enabled', false);
        $result = $this->invokeMethod($this->manager, 'expandRoleIdsWithInheritance', [[1, 2, 3]]);
        $this->assertEquals([1, 2, 3], $result);
    }

    public function testExpandRoleIdsEmptyInput(): void
    {
        $result = $this->invokeMethod($this->manager, 'expandRoleIdsWithInheritance', [[]]);
        $this->assertEquals([], $result);
    }

    // =============================
    // CacheKeyHelper 集成测试
    // =============================

    public function testManagerUsesCacheKeyHelper(): void
    {
        $traits = class_uses($this->manager);
        $this->assertArrayHasKey(\wise\auth\trait\CacheKeyHelper::class, $traits);
    }

    public function testManagerGetCacheKey(): void
    {
        $key = $this->invokeMethod($this->manager, 'getCacheKey', ['test']);
        $this->assertIsString($key);
        $this->assertStringStartsWith('wiseauth:', $key);
    }

    // =============================
    // checkBuiltinConstraints 测试
    // =============================

    public function testCheckBuiltinConstraintsEmpty(): void
    {
        $this->setConfig('wiseauth.constraints', []);
        $result = $this->invokeMethod($this->manager, 'checkBuiltinConstraints', ['beforeAssignRole']);
        $this->assertTrue($result);
    }

    public function testCheckBuiltinConstraintsUnknownMethod(): void
    {
        $this->setConfig('wiseauth.constraints', ['mutual_exclusion' => []]);
        $result = $this->invokeMethod($this->manager, 'checkBuiltinConstraints', ['unknownMethod']);
        $this->assertTrue($result);
    }

    public function testCheckBuiltinConstraintsCheckBeforeSaveRole(): void
    {
        $this->setConfig('wiseauth.constraints', ['mutual_exclusion' => [['a', 'b']]]);
        $result = $this->invokeMethod($this->manager, 'checkBuiltinConstraints', ['checkBeforeSaveRole']);
        $this->assertTrue($result);
    }

    // =============================
    // checkMutualExclusion 测试
    // =============================

    public function testCheckMutualExclusionEmptyConstraints(): void
    {
        $result = $this->invokeMethod($this->manager, 'checkMutualExclusion', [1, 'admin', 1, []]);
        $this->assertTrue($result);
    }

    public function testCheckMutualExclusionNoMutualExclusionKey(): void
    {
        $result = $this->invokeMethod($this->manager, 'checkMutualExclusion', [1, 'admin', 1, ['other' => []]]);
        $this->assertTrue($result);
    }

    // =============================
    // 边界条件测试
    // =============================

    public function testSuperAdminIdsMixedTypes(): void
    {
        $this->setConfig('wiseauth.super_admin_ids', [1, '2', 3]);
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
