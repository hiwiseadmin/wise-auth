<?php
/**
 * PermissionRegistrar 单元测试
 *
 * 测试权限注册、注解解析、缓存管理等核心方法。
 */
namespace wise\auth\tests;

use Mockery;
use wise\auth\service\PermissionRegistrar;

class PermissionRegistrarTest extends TestCase
{
    /** @var PermissionRegistrar */
    protected $registrar;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setConfig('wiseauth.cache_enabled', false);
        $this->registrar = new PermissionRegistrar();
    }

    // =============================
    // parseAnnotationParams 测试
    // =============================

    public function testParseAnnotationParamsSingleParam(): void
    {
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', ['ident="admin.user.list"']);
        $this->assertEquals(['ident' => 'admin.user.list'], $result);
    }

    public function testParseAnnotationParamsMultipleParams(): void
    {
        $input = 'ident="admin.user.list", name="用户列表", type="route"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.user.list', $result['ident']);
        $this->assertEquals('用户列表', $result['name']);
        $this->assertEquals('route', $result['type']);
    }

    public function testParseAnnotationParamsWithSingleQuotes(): void
    {
        $input = "ident='admin.user.list', name='User List'";
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.user.list', $result['ident']);
        $this->assertEquals('User List', $result['name']);
    }

    public function testParseAnnotationParamsMixedQuotes(): void
    {
        $input = 'ident="admin.user.list", name=\'User List\'';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.user.list', $result['ident']);
        $this->assertEquals('User List', $result['name']);
    }

    public function testParseAnnotationParamsEmptyString(): void
    {
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', ['']);
        $this->assertEquals([], $result);
    }

    public function testParseAnnotationParamsNoQuotes(): void
    {
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', ['ident=value']);
        $this->assertEquals([], $result);
    }

    public function testParseAnnotationParamsWithRoute(): void
    {
        $input = 'ident="admin.index", name="首页", type="route", route="/admin/index/index", method="*"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.index', $result['ident']);
        $this->assertEquals('首页', $result['name']);
        $this->assertEquals('route', $result['type']);
        $this->assertEquals('/admin/index/index', $result['route']);
        $this->assertEquals('*', $result['method']);
    }

    public function testParseAnnotationParamsNumericValues(): void
    {
        $input = 'ident="admin.user", sort="10", status="1"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.user', $result['ident']);
        $this->assertEquals('10', $result['sort']);
        $this->assertEquals('1', $result['status']);
    }

    public function testParseAnnotationParamsWithSpecialChars(): void
    {
        $input = 'ident="admin.crud.*", route="/admin/*", description="CRUD operations"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.crud.*', $result['ident']);
        $this->assertEquals('/admin/*', $result['route']);
        $this->assertEquals('CRUD operations', $result['description']);
    }

    // =============================
    // parseAnnotationPermissions 测试
    // =============================

    public function testParseAnnotationPermissionsNoMatches(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'wiseauth_test_');
        file_put_contents($tmpFile, "<?php\n// no annotations here\nclass Test {}");
        try {
            $result = $this->invokeMethod($this->registrar, 'parseAnnotationPermissions', [$tmpFile, 'permission']);
            $this->assertEquals([], $result);
        } finally {
            @unlink($tmpFile);
        }
    }

    public function testParseAnnotationPermissionsInvalidFile(): void
    {
        // 抑制 file_get_contents 对不存在文件的警告
        $currentLevel = error_reporting();
        error_reporting($currentLevel & ~E_WARNING);
        try {
            $result = $this->invokeMethod($this->registrar, 'parseAnnotationPermissions', ['/nonexistent/file_that_does_not_exist.php', 'permission']);
            $this->assertEquals([], $result);
        } finally {
            error_reporting($currentLevel);
        }
    }

    // =============================
    // hasPermission 测试
    // =============================

    public function testHasPermissionUsesGetPermissionMap(): void
    {
        // 缓存已禁用，应直接查数据库
        $this->registrar = Mockery::mock(PermissionRegistrar::class)->makePartial();
        $this->registrar->shouldReceive('getPermissionMap')->andReturn([
            'admin.user.list' => ['id' => 1, 'ident' => 'admin.user.list'],
            'admin.user.create' => ['id' => 2, 'ident' => 'admin.user.create'],
        ]);

        $this->assertTrue($this->registrar->hasPermission('admin.user.list'));
        $this->assertTrue($this->registrar->hasPermission('admin.user.create'));
        $this->assertFalse($this->registrar->hasPermission('admin.user.delete'));
        $this->assertFalse($this->registrar->hasPermission('nonexistent'));
    }

    // =============================
    // CacheKeyHelper 集成测试
    // =============================

    public function testRegistrarUsesCacheKeyHelper(): void
    {
        $traits = class_uses($this->registrar);
        $this->assertArrayHasKey(\wise\auth\trait\CacheKeyHelper::class, $traits);
    }

    public function testRegistrarGetCacheKey(): void
    {
        $key = $this->invokeMethod($this->registrar, 'getCacheKey', ['permission_map']);
        $this->assertEquals('wiseauth:permission_map', $key);
    }

    // =============================
    // 边界条件测试
    // =============================

    public function testParseAnnotationParamsEscapedQuotes(): void
    {
        $input = 'ident="admin.user", name="Test \"Name\""';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        // 引号内的引号会被匹配到，但不影响核心解析
        $this->assertEquals('admin.user', $result['ident']);
    }

    public function testParseAnnotationParamsUnicodeChinese(): void
    {
        $input = 'ident="admin.用户管理", name="用户管理模块", type="custom"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('admin.用户管理', $result['ident']);
        $this->assertEquals('用户管理模块', $result['name']);
    }

    public function testParseAnnotationParamsWithoutIdent(): void
    {
        $input = 'name="Test", type="route"';
        $result = $this->invokeMethod($this->registrar, 'parseAnnotationParams', [$input]);
        $this->assertEquals('Test', $result['name']);
        $this->assertArrayNotHasKey('ident', $result);
    }
}
